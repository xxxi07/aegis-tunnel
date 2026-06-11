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

static void tun_setup_routing(const char *name, const char *allowed_ips, const char *nat_if)
{
    tun_enable_forwarding();
    tun_set_fwmark_rule(TUN_FWMARK);
    tun_set_nat(allowed_ips, nat_if);
    tun_allow_forward(name);
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
    tun_setup_routing(name, tun_route ? tun_route : "10.0.0.0/24", tun_nat_if);

    int listen_fd = listen_on_port(listen_port);
    if (listen_fd < 0) { close(tun_fd); return 1; }

    log_info("tun-server", "%s (%s/%s) :%d route=%s peers=%d",
             name, tun_ip && tun_ip[0] ? tun_ip : "dhcp", tun_netmask,
             listen_port, tun_route ? tun_route : "10.0.0.0/24", g_peer_count);

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
    close(listen_fd); close(tun_fd);
    return 0;
}

/* ─── TUN Client ──────────────────────────────────────────────── */
int mode_tun_client(int listen_port, const char *remote_host, int remote_port,
                    const char *tun_name,
                    const char *tun_ip, const char *tun_netmask,
                    const char *tun_route,
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

    int tunnel_fd = connect_to_host(remote_host, remote_port);
    if (tunnel_fd < 0) { close(tun_fd); return 1; }

    tun_set_fwmark(tunnel_fd, TUN_FWMARK);

    log_info("tun-client", "%s (%s/%s) → %s:%d route=%s",
             name, tun_ip && tun_ip[0] ? tun_ip : "dhcp", tun_netmask,
             remote_host, remote_port, tun_route ? tun_route : "(none)");

    session_keys_t keys;
    if (handshake_client(tunnel_fd, g_asym_priv, g_asym_peers[0], hs_timeout, &keys) != 0)
        { log_warn("tun-client", "handshake failed"); close(tunnel_fd); close(tun_fd); return 1; }
    if (handshake_key_confirm_client(tunnel_fd, &keys, hs_timeout) != 0)
        { secure_memzero(&keys, sizeof(keys)); close(tunnel_fd); close(tun_fd); return 1; }

    tunnel_t tun; tunnel_init(&tun, tun_fd, tunnel_fd, keys.enc_key, keys.dec_key);
    tun.keepalive_sec = keepalive; tun.rekey_sec = 120; tun.psk = psk; tun.psk_len = psk_len;

    int r = tunnel_run(&tun);
    secure_memzero(&keys, sizeof(keys));
    close(tunnel_fd); close(tun_fd);
    return r == 0 ? 0 : 1;
}
