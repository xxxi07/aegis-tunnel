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
    if (tun_route && tun_route[0]) tun_add_route(tun_route, name);
    tun_enable_forwarding();
    tun_set_nat(tun_route ? tun_route : "10.0.0.0/24", tun_nat_if);
    tun_allow_forward(name);

    int listen_fd = listen_on_port(listen_port);
    if (listen_fd < 0) { close(tun_fd); return 1; }

    log_info("tun-server", "%s (%s/%s) listening on :%d",
             name, tun_ip && tun_ip[0] ? tun_ip : "dhcp", tun_netmask, listen_port);

    while (g_running) {
        struct sockaddr_in ca; socklen_t al = sizeof(ca);
        int client_fd = accept(listen_fd, (struct sockaddr *)&ca, &al);
        if (client_fd < 0) { if (errno == EINTR) continue; break; }
        if (g_active_conns >= g_max_conns) { close(client_fd); continue; }

        char ip[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &ca.sin_addr, ip, sizeof(ip));
        log_info("tun-server", "client %s:%d", ip, ntohs(ca.sin_port));

        pid_t pid = fork();
        if (pid < 0) { close(client_fd); continue; }
        if (pid == 0) {
            close(listen_fd);
            signal(SIGCHLD, SIG_DFL);

            session_keys_t keys;
            if (handshake_server(client_fd, g_asym_priv, g_asym_peer, hs_timeout, &keys) != 0)
                { log_warn("tun-server", "handshake failed"); close(client_fd); _exit(1); }

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
    if (tun_route && tun_route[0]) tun_add_route(tun_route, name);

    int tunnel_fd = connect_to_host(remote_host, remote_port);
    if (tunnel_fd < 0) { close(tun_fd); return 1; }

    log_info("tun-client", "%s (%s/%s) → %s:%d",
             name, tun_ip && tun_ip[0] ? tun_ip : "dhcp", tun_netmask,
             remote_host, remote_port);

    session_keys_t keys;
    if (handshake_client(tunnel_fd, g_asym_priv, g_asym_peer, hs_timeout, &keys) != 0)
        { log_warn("tun-client", "handshake failed"); close(tunnel_fd); close(tun_fd); return 1; }

    tunnel_t tun; tunnel_init(&tun, tun_fd, tunnel_fd, keys.enc_key, keys.dec_key);
    tun.keepalive_sec = keepalive; tun.rekey_sec = 120; tun.psk = psk; tun.psk_len = psk_len;

    int r = tunnel_run(&tun);
    secure_memzero(&keys, sizeof(keys));
    close(tunnel_fd); close(tun_fd);
    return r == 0 ? 0 : 1;
}
