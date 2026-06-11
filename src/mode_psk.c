/*
 * mode_psk.c — Asymmetric handshake server/client modes
 */
#include "main.h"
#include "protocol/handshake.h"
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

/*
 * Try handshake with each known peer key.  Returns 0 on success
 * (keys filled), -1 if no peer key works.
 * Like SSH authorized_keys: any known peer can connect.
 */
static int try_handshake_server(int fd, session_keys_t *keys, int timeout_ms)
{
    for (int i = 0; i < g_peer_count; i++) {
        if (handshake_server(fd, g_asym_priv, g_asym_peers[i], timeout_ms, keys) == 0) {
            log_info("server", "peer #%d authenticated", i);
            return 0;
        }
    }
    return -1;
}

static int try_handshake_client(int fd, session_keys_t *keys, int timeout_ms)
{
    /* Client only knows one peer (the server) */
    return handshake_client(fd, g_asym_priv, g_asym_peers[0], timeout_ms, keys);
}

/* ─── Server ──────────────────────────────────────────────────── */
int mode_psk_server(int listen_port, const char *remote_host, int remote_port,
                    const uint8_t *psk, size_t psk_len, int hs_timeout, int keepalive)
{
    int listen_fd = listen_on_port(listen_port);
    if (listen_fd < 0) return 1;

    log_info("server", "port %d → %s:%d (max %d, %d peers)",
             listen_port, remote_host, remote_port, g_max_conns, g_peer_count);

    while (g_running) {
        struct sockaddr_in ca; socklen_t al = sizeof(ca);
        int client_fd = accept(listen_fd, (struct sockaddr *)&ca, &al);
        if (client_fd < 0) { if (errno == EINTR) continue; perror("accept"); continue; }
        if (g_active_conns >= g_max_conns) { close(client_fd); continue; }

        char ip[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &ca.sin_addr, ip, sizeof(ip));
        log_info("server", "#%d %s:%d", (int)g_active_conns+1, ip, ntohs(ca.sin_port));
        set_socket_timeout(client_fd, hs_timeout);

        pid_t pid = fork();
        if (pid < 0) { close(client_fd); continue; }
        if (pid == 0) {
            close(listen_fd); signal(SIGCHLD, SIG_DFL);

            session_keys_t keys;
            if (try_handshake_server(client_fd, &keys, hs_timeout) != 0)
                { log_warn("server", "handshake failed (tried %d peers)", g_peer_count); close(client_fd); _exit(1); }
            if (handshake_key_confirm_server(client_fd, &keys, hs_timeout) != 0)
                { secure_memzero(&keys, sizeof(keys)); close(client_fd); _exit(1); }

            int remote_fd = connect_to_host(remote_host, remote_port);
            if (remote_fd < 0) { close(client_fd); _exit(1); }

            tunnel_t tun; tunnel_init(&tun, remote_fd, client_fd, keys.enc_key, keys.dec_key);
            tun.keepalive_sec = keepalive; tun.rekey_sec = 120; tun.psk = psk; tun.psk_len = psk_len;
            int r = tunnel_run(&tun);
            secure_memzero(&keys, sizeof(keys));
            close(remote_fd); close(client_fd);
            _exit(r == 0 ? 0 : 1);
        }
        g_active_conns++; close(client_fd);
    }
    while (waitpid(-1, NULL, 0) > 0) {}
    close(listen_fd);
    return 0;
}

/* ─── Client ──────────────────────────────────────────────────── */
int mode_psk_client(int listen_port, const char *remote_host, int remote_port,
                    const uint8_t *psk, size_t psk_len, int hs_timeout, int keepalive)
{
    int listen_fd = listen_on_port(listen_port);
    if (listen_fd < 0) return 1;

    log_info("client", "port %d → %s:%d", listen_port, remote_host, remote_port);

    while (g_running) {
        struct sockaddr_in la; socklen_t al = sizeof(la);
        int local_fd = accept(listen_fd, (struct sockaddr *)&la, &al);
        if (local_fd < 0) { if (errno == EINTR) continue; perror("accept"); continue; }
        if (g_active_conns >= g_max_conns) { close(local_fd); continue; }

        int tunnel_fd = connect_to_host(remote_host, remote_port);
        if (tunnel_fd < 0) { close(local_fd); continue; }
        set_socket_timeout(tunnel_fd, hs_timeout);

        session_keys_t keys;
        if (try_handshake_client(tunnel_fd, &keys, hs_timeout) != 0)
            { log_warn("client", "handshake failed"); close(local_fd); close(tunnel_fd); continue; }
        if (handshake_key_confirm_client(tunnel_fd, &keys, hs_timeout) != 0)
            { secure_memzero(&keys, sizeof(keys)); close(local_fd); close(tunnel_fd); continue; }

        tunnel_t tun; tunnel_init(&tun, local_fd, tunnel_fd, keys.enc_key, keys.dec_key);
        tun.keepalive_sec = keepalive; tun.rekey_sec = 120; tun.psk = psk; tun.psk_len = psk_len;

        g_active_conns++;
        int r = tunnel_run(&tun);
        g_active_conns--;
        secure_memzero(&keys, sizeof(keys));
        close(local_fd); close(tunnel_fd);
        if (r != 0) log_error("client", "tunnel error");
    }
    close(listen_fd);
    return 0;
}
