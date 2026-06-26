/*
 * mode_tun.c — TUN VPN server/client modes
 */
#include "main.h"
#include "mode_common.h"
#include "protocol/handshake.h"
#include "tunnel/tun.h"
#include "tunnel/tunnel.h"
#include "util/log.h"
#include "util/util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#define TUN_FWMARK       51820

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

/* ─── TUN Server (multi-client, fork-per-connection) ────────────── */

/*
 * Architecture:
 *
 *   Parent:  owns tun_fd + listen_fd (MPTCP-capable).
 *            Accepts connections and forks a child for each.
 *
 *   Child N: shares tun_fd (via fork inheritance) and owns the
 *            TCP/MPTCP encrypted_fd to client N.  Runs the standard
 *            tunnel event loop (tunnel_run) which polls tun_fd and
 *            encrypted_fd.  The kernel TUN driver ensures each IP
 *            packet is delivered to exactly one reader.
 *
 *             tun_fd (shared)
 *              ┌─────┐
 *   Parent ───►│ TUN │◄── child 1 ── TCP/MPTCP ──► client A (10.0.0.2)
 *   (accept)   └─────┘◄── child 2 ── TCP/MPTCP ──► client B (10.0.0.3)
 *
 *   With MPTCP: a single client may have multiple subflows over
 *   different network paths — all handled transparently by the
 *   kernel.  Each MPTCP connection still appears as one fd.
 */

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
        else if (!strchr(tun_route, ','))
            tun_add_route(tun_route, name);
        /* multi-subnet (comma-separated): tun_setup_routing handles it */
    }
    tun_setup_routing(name, tun_route, tun_nat_if, 1 /* server */);
    tun_run_postup(postup, name);

    /* MPTCP listener: accepts both MPTCP and regular TCP clients.
     * Falls back to TCP if MPTCP is unavailable (kernel < 5.6). */
    int listen_fd = listen_on_port_mptcp(listen_port);
    if (listen_fd < 0) { close(tun_fd); return 1; }

    log_info("tun-server", "%s (%s/%s) :%d route=%s peers=%d",
             name, tun_ip && tun_ip[0] ? tun_ip : "dhcp", tun_netmask,
             listen_port, tun_route ? tun_route : "(none)", g_peer_count);

    /* Accept loop — children share tun_fd directly */
    (void)psk; (void)psk_len;
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
            if (try_handshake_server(client_fd, &keys, hs_timeout) < 0)
                { log_warn("tun-server", "handshake failed"); close(client_fd); _exit(1); }
            if (handshake_key_confirm_server(client_fd, &keys, hs_timeout) != 0)
                { secure_memzero(&keys, sizeof(keys)); close(client_fd); _exit(1); }

            tunnel_t tun; tunnel_init(&tun, tun_fd, client_fd, keys.enc_key, keys.dec_key);
            tun.keepalive_sec = keepalive;

            int r = tunnel_run(&tun);
            secure_memzero(&keys, sizeof(keys));
            close(client_fd); _exit(r == 0 ? 0 : 1);
        }
        g_active_conns++; close(client_fd);
    }
    while (waitpid(-1, NULL, 0) > 0) {}

    tun_run_postdown(postdown, name);
    tun_teardown(name, 1 /* server */);
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

    log_info("tun-client", "%s (%s/%s) route=%s peers=%d (auto-reconnect)",
             name, tun_ip && tun_ip[0] ? tun_ip : "dhcp", tun_netmask,
             tun_route ? tun_route : "(none)", g_peer_count > 0 ? g_peer_count : 1);

    /* Reconnect loop — try each configured peer in round-robin */
    int retry_delay = 0;
    int peer_idx    = 0;
    int use_single  = (remote_host && remote_host[0]) ? 1 : 0;  /* -r overrides multi-peer */
    int peer_count  = (!use_single && g_peer_count > 0) ? g_peer_count : 1;

    while (g_running) {
        const char *host; int port; int pi;

        if (use_single) {
            host = remote_host; port = remote_port; pi = 0;
        } else if (g_peer_endpoints[peer_idx][0]) {
            /* Parse endpoint from config; auto-append :9000 if no port */
            char ep_buf[320];
            snprintf(ep_buf, sizeof(ep_buf), "%s", g_peer_endpoints[peer_idx]);
            if (!strrchr(ep_buf, ':')) {
                size_t el = strlen(ep_buf);
                snprintf(ep_buf + el, sizeof(ep_buf) - el, ":9000");
            }
            char *hp = NULL;
            if (parse_host_port(ep_buf, &hp, &port) != 0) {
                log_warn("tun-client", "bad endpoint for peer #%d", peer_idx);
                peer_idx = (peer_idx + 1) % peer_count; continue;
            }
            host = hp; pi = peer_idx;
        } else {
            host = remote_host; port = remote_port; pi = 0;
        }

        log_info("tun-client", "trying peer #%d: %s:%d", pi, host, port);

        /* Use MPTCP when -M is specified (kernel manages subflows).
         * MPTCP is transparent to the application — tunnel_run()
         * sees a single reliable byte stream regardless of how many
         * subflows the kernel creates. */
        int tunnel_fd;
        if (g_tun_multipath > 1)
            tunnel_fd = connect_to_host_mptcp(host, port, TUN_FWMARK);
        else
            tunnel_fd = connect_to_host(host, port, TUN_FWMARK);

        if (tunnel_fd < 0) {
            if (retry_delay == 0) log_error("tun-client", "cannot connect");
            peer_idx = (peer_idx + 1) % peer_count; goto retry;
        }

        session_keys_t keys;
        if (handshake_client(tunnel_fd, g_asym_priv, g_asym_peers[pi], hs_timeout, &keys) == 0 &&
            handshake_key_confirm_client(tunnel_fd, &keys, hs_timeout) == 0) {
            log_info("tun-client", "peer #%d authenticated", pi);

            /* Single tunnel_run() — MPTCP multipath is transparent */
            tunnel_t tun;
            tunnel_init(&tun, tun_fd, tunnel_fd, keys.enc_key, keys.dec_key);
            tun.keepalive_sec = keepalive;

            int r = tunnel_run(&tun);
            secure_memzero(&keys, sizeof(keys));
            close(tunnel_fd);
            if (r == 0) break;
            log_warn("tun-client", "tunnel dropped, reconnecting...");
        } else {
            log_warn("tun-client", "handshake failed with peer #%d", pi);
            close(tunnel_fd);
            peer_idx = (peer_idx + 1) % peer_count;  /* try next peer on failure */
        }

    retry:
        if (!g_running) break;
        if (retry_delay == 0) retry_delay = 1;
        else if (retry_delay < 30) retry_delay *= 2;
        log_info("tun-client", "retry in %ds...", retry_delay);
        sleep((unsigned)retry_delay);
    }

    tun_run_postdown(postdown, name);
    tun_teardown(name, 0 /* client */);
    close(tun_fd);
    return 0;
}
