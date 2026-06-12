/*
 * mode_tun.c — TUN VPN server/client modes
 */
#include "main.h"
#include "protocol/handshake.h"
#include "tunnel/tun.h"
#include "tunnel/tunnel.h"
#include "util/log.h"
#include "util/util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#define TUN_FWMARK  51820

/*
 * Set up routing based on role (server vs client).
 *
 * Server: enable forwarding → fwmark → routes per AllowedIPs →
 *         NAT per AllowedIPs → FORWARD rules → PostUp
 * Client: fwmark → routes per AllowedIPs → PostUp
 */
static void tun_setup_routing(const char *name, const char *allowed_ips,
                               const char *nat_if, int is_server)
{
    if (is_server) {
        /* Server: routes in main table, no fwmark policy needed */
        tun_enable_forwarding();
        if (allowed_ips && allowed_ips[0]) {
            tun_add_routes_multi(allowed_ips, name);
            tun_set_nat_multi(allowed_ips, nat_if);
        }
        tun_allow_forward(name);
    }
    /* Client routing is handled inline in mode_tun_client:
     * full tunnel → custom table + fwmark rule
     * split tunnel → main table, no fwmark rule needed */
}

/*
 * Execute PostUp / PostDown scripts if set.
 * WireGuard-style: %i is replaced with interface name.
 */
static void tun_run_postup(const char *script, const char *name)
{
    if (script && script[0]) {
        log_info("tun", "PostUp: %s", script);
        tun_exec_script(script, name);
    }
}

static void tun_run_postdown(const char *script, const char *name)
{
    if (script && script[0]) {
        log_info("tun", "PostDown: %s", script);
        tun_exec_script(script, name);
    }
}

static int try_handshake_server(int fd, session_keys_t *keys, int timeout_ms)
{
    for (int i = 0; i < g_peer_count; i++) {
        if (handshake_server(fd, g_asym_priv, g_asym_peers[i], timeout_ms, keys) == 0)
            { log_info("tun-server", "peer #%d authenticated", i); return 0; }
    }
    return -1;
}

/* ─── TUN Server ──────────────────────────────────────────────── */
int mode_tun_server(int listen_port,
                    const char *tun_name,
                    const char *tun_ip, const char *tun_netmask,
                    const char *tun_route, const char *tun_nat_if,
                    const char *postup, const char *postdown,
                    const uint8_t *psk, size_t psk_len,
                    int hs_timeout, int keepalive)
{
    char name[16]; strncpy(name, tun_name, 15); name[15] = '\0';
    int tun_fd = tun_create(name);
    if (tun_fd < 0) return 1;

    if (tun_ip && tun_ip[0]) tun_set_ip(name, tun_ip, tun_netmask);
    tun_up(name);

    if (tun_route && tun_route[0]) {
        if (strcmp(tun_route, "0.0.0.0/0") == 0 || strcmp(tun_route, "::/0") == 0)
            tun_add_full_tunnel(name);
        else
            tun_add_route(tun_route, name);
    }
    tun_setup_routing(name, tun_route, tun_nat_if, 1 /* server */);
    tun_run_postup(postup, name);

    int listen_fd = listen_on_port(listen_port);
    if (listen_fd < 0) { close(tun_fd); return 1; }

    log_info("tun-server", "%s (%s/%s) :%d route=%s peers=%d",
             name, tun_ip && tun_ip[0] ? tun_ip : "dhcp", tun_netmask,
             listen_port, tun_route ? tun_route : "(none)", g_peer_count);

    while (g_running) {
        struct sockaddr_in ca; socklen_t al = sizeof(ca);
        int client_fd = accept(listen_fd, (struct sockaddr *)&ca, &al);
        if (client_fd < 0) { if (errno == EINTR) continue; break; }
        if (g_active_conns >= g_max_conns) { close(client_fd); continue; }

        tun_set_fwmark(client_fd, TUN_FWMARK);

        char ip[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &ca.sin_addr, ip, sizeof(ip));
        log_info("tun-server", "client %s:%d", ip, ntohs(ca.sin_port));

        pid_t pid = fork();
        if (pid < 0) { close(client_fd); continue; }
        if (pid == 0) {
            close(listen_fd); signal(SIGCHLD, SIG_DFL);

            session_keys_t keys;
            if (try_handshake_server(client_fd, &keys, hs_timeout) != 0)
                { log_warn("tun-server", "handshake failed (tried %d peers)", g_peer_count); close(client_fd); _exit(1); }
            if (handshake_key_confirm_server(client_fd, &keys, hs_timeout) != 0)
                { secure_memzero(&keys, sizeof(keys)); close(client_fd); _exit(1); }

            tunnel_t tun; tunnel_init(&tun, tun_fd, client_fd, keys.enc_key, keys.dec_key);
            tun.keepalive_sec = keepalive; tun.rekey_sec = 120; tun.psk = psk; tun.psk_len = psk_len;

            int r = tunnel_run(&tun);
            secure_memzero(&keys, sizeof(keys));
            close(client_fd); _exit(r == 0 ? 0 : 1);
        }
        g_active_conns++; close(client_fd);
    }
    while (waitpid(-1, NULL, 0) > 0) {}

    tun_run_postdown(postdown, name);
    close(listen_fd); close(tun_fd);
    return 0;
}

/* ─── TUN Client ──────────────────────────────────────────────── */
int mode_tun_client(int listen_port, const char *remote_host, int remote_port,
                    const char *tun_name,
                    const char *tun_ip, const char *tun_netmask,
                    const char *tun_route,
                    const char *postup, const char *postdown,
                    const uint8_t *psk, size_t psk_len,
                    int hs_timeout, int keepalive)
{
    char name[16]; strncpy(name, tun_name, 15); name[15] = '\0';
    int tun_fd = tun_create(name);
    if (tun_fd < 0) return 1;

    if (tun_ip && tun_ip[0]) tun_set_ip(name, tun_ip, tun_netmask);
    tun_up(name);

    int is_full_tunnel = 0;
    if (tun_route && tun_route[0]) {
        if (strcmp(tun_route, "0.0.0.0/0") == 0 || strcmp(tun_route, "::/0") == 0) {
            tun_add_full_tunnel(name);
            tun_set_fwmark_rule(TUN_FWMARK);  /* only full tunnel needs fwmark bypass */
            is_full_tunnel = 1;
        } else {
            tun_add_route(tun_route, name);
        }
    }
    /* Add multi-subnet routes from AllowedIPs (client side) */
    if (tun_route && tun_route[0] && strchr(tun_route, ','))
        tun_add_routes_multi(tun_route, name);
    (void)is_full_tunnel;
    tun_run_postup(postup, name);

    log_info("tun-client", "%s (%s/%s) → %s:%d route=%s (auto-reconnect)",
             name, tun_ip && tun_ip[0] ? tun_ip : "dhcp", tun_netmask,
             remote_host, remote_port, tun_route ? tun_route : "(none)");

    /* Reconnect loop */
    int retry_delay = 0;
    while (g_running) {
        int tunnel_fd = connect_to_host(remote_host, remote_port, TUN_FWMARK);
        if (tunnel_fd < 0) { if (retry_delay == 0) log_error("tun-client", "cannot connect"); goto retry; }

        session_keys_t keys;
        if (handshake_client(tunnel_fd, g_asym_priv, g_asym_peers[0], hs_timeout, &keys) == 0 &&
            handshake_key_confirm_client(tunnel_fd, &keys, hs_timeout) == 0) {

            tunnel_t tun; tunnel_init(&tun, tun_fd, tunnel_fd, keys.enc_key, keys.dec_key);
            tun.keepalive_sec = keepalive; tun.rekey_sec = 120; tun.psk = psk; tun.psk_len = psk_len;

            int r = tunnel_run(&tun);
            secure_memzero(&keys, sizeof(keys));
            close(tunnel_fd);
            if (r == 0) break;
            log_warn("tun-client", "tunnel dropped, reconnecting...");
        } else {
            log_warn("tun-client", "handshake failed");
            close(tunnel_fd);
        }

    retry:
        if (!g_running) break;
        if (retry_delay == 0) retry_delay = 1;
        else if (retry_delay < 30) retry_delay *= 2;
        log_info("tun-client", "retry in %ds...", retry_delay);
        sleep((unsigned)retry_delay);
    }

    tun_run_postdown(postdown, name);
    close(tun_fd);
    return 0;
}
