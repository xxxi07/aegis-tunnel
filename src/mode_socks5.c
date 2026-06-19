/*
 * mode_socks5.c — SOCKS5 proxy mode (RFC 1928 CONNECT)
 *
 * Client: listens locally, accepts SOCKS5 connections, resolves the
 *         target address, encrypts traffic through the AEGIS tunnel
 *         to the server.
 *
 * Server: accepts encrypted connections, reads the target address
 *         from the first post-handshake frame, connects to the
 *         actual destination, and relays decrypted traffic.
 *
 * Protocol extension (post-handshake):
 *   After KEY_CONFIRM, the client sends a CONNECT_REQUEST frame
 *   (nonce_ctr=1) containing the target host:port.  The server
 *   reads it, connects to the target, then both sides enter the
 *   normal tunnel event loop (nonce_ctr starting at 2).
 */
#include "main.h"
#include "mode_common.h"
#include "protocol/handshake.h"
#include "proxy/socks5.h"
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

/* ─── Connect request wire format ───────────────────────────────── */
/*
 * Payload: [port:2 BE][host_len:2 BE][host:host_len bytes]
 *
 * Wire frame (encrypted with session key, nonce_ctr=1):
 *   [header:4][payload:N][tag:16]
 */

static void build_connect_req(uint8_t *out, size_t *olen,
                              const char *host, size_t host_len,
                              uint16_t port)
{
    out[0] = (uint8_t)(port >> 8);
    out[1] = (uint8_t)(port);
    out[2] = (uint8_t)(host_len >> 8);
    out[3] = (uint8_t)(host_len);
    memcpy(out + 4, host, host_len);
    *olen = 4 + host_len;
}

static int parse_connect_req(const uint8_t *p, size_t len,
                             char *host, size_t *host_len,
                             uint16_t *port)
{
    if (len < 4) return -1;
    *port      = (uint16_t)((p[0] << 8) | p[1]);
    *host_len  = ((size_t)p[2] << 8) | p[3];
    if (len < 4 + *host_len) return -1;
    if (*host_len > 255)     return -1;
    memcpy(host, p + 4, *host_len);
    host[*host_len] = '\0';
    return 0;
}

/* ─── Send connect request (client side) ───────────────────────── */

static int send_connect_req(int fd, const char *host, size_t host_len,
                            uint16_t port,
                            const uint8_t enc_key[AEGIS_KEY_LEN])
{
    uint8_t req[260]; size_t rlen;
    build_connect_req(req, &rlen, host, host_len, port);

    uint8_t wb[FRAME_HEADER_LEN + sizeof(req) + AEGIS_TAG_LEN];
    size_t wl = 0;
    if (frame_build(wb, &wl, FRAME_DATA, FLAG_NONE, req, rlen,
                    1 /* nonce_ctr */, enc_key) != 0)
        return -1;
    return send_all(fd, wb, wl);
}

/* ─── Receive connect request (server side) ────────────────────── */

static int recv_connect_req(int fd, char *host, size_t *host_len,
                            uint16_t *port,
                            const uint8_t dec_key[AEGIS_KEY_LEN])
{
    /* Read frame header first to learn payload length */
    uint8_t hdr[FRAME_HEADER_LEN];
    if (recv_all(fd, hdr, FRAME_HEADER_LEN) != 0) {
        fprintf(stderr, "[socks5-server] failed to read connect request header\n");
        return -1;
    }
    size_t p_len = (size_t)(((uint16_t)hdr[2] << 8) | hdr[3]);
    if (p_len < 4 || p_len > 260) {  /* min 4 bytes (port+host_len), max 260 */
        fprintf(stderr, "[socks5-server] bad connect request payload len %zu\n", p_len);
        return -1;
    }

    size_t total = FRAME_HEADER_LEN + p_len + AEGIS_TAG_LEN;
    uint8_t wb[FRAME_HEADER_LEN + 260 + AEGIS_TAG_LEN];
    memcpy(wb, hdr, FRAME_HEADER_LEN);
    if (recv_all(fd, wb + FRAME_HEADER_LEN, total - FRAME_HEADER_LEN) != 0) {
        fprintf(stderr, "[socks5-server] failed to read connect request body\n");
        return -1;
    }

    uint8_t ty, fl, req[260]; size_t rlen;
    if (frame_parse(wb, total, &ty, &fl, req, &rlen, 1 /* nonce_ctr */, dec_key) != 0) {
        fprintf(stderr, "[socks5-server] connect request auth failed\n");
        return -1;
    }
    return parse_connect_req(req, rlen, host, host_len, port);
}

/* ════════════════════════════════════════════════════════════════
 * SOCKS5 Server (remote side — connects to actual target)
 * ════════════════════════════════════════════════════════════════ */

int mode_socks5_server(int listen_port,
                       const uint8_t *psk, size_t psk_len,
                       int hs_timeout, int keepalive)
{
    int listen_fd = listen_on_port(listen_port);
    if (listen_fd < 0) return 1;

    log_info("socks5-server", "port %d (max %d, %d peers)",
             listen_port, g_max_conns, g_peer_count);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_DFL;
    sa.sa_flags   = SA_RESTART | SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    while (g_running) {
        struct sockaddr_in ca; socklen_t al = sizeof(ca);
        int client_fd = accept(listen_fd, (struct sockaddr *)&ca, &al);
        if (client_fd < 0) { if (errno == EINTR) continue; perror("accept"); continue; }
        if (g_active_conns >= g_max_conns) { close(client_fd); continue; }

        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ca.sin_addr, ip, sizeof(ip));
        log_info("socks5-server", "#%d %s:%d", (int)g_active_conns + 1,
                 ip, ntohs(ca.sin_port));

        /* Anti-DoS: rate-limit handshake attempts per source IP */
        if (handshake_rate_check(ip, (int64_t)time(NULL)) < 0) {
            close(client_fd); continue;
        }

        pid_t pid = fork();
        if (pid < 0) { close(client_fd); continue; }

        if (pid == 0) {
            close(listen_fd);
            signal(SIGCHLD, SIG_DFL);

            /* ── Handshake ── */
            session_keys_t keys;
            int peer_idx = try_handshake_server(client_fd, &keys, hs_timeout);
            if (peer_idx < 0) {
                log_warn("socks5-server", "handshake failed (tried %d peers)",
                         g_peer_count);
                close(client_fd); _exit(1);
            }
            if (handshake_key_confirm_server(client_fd, &keys, hs_timeout) != 0) {
                secure_memzero(&keys, sizeof(keys));
                close(client_fd); _exit(1);
            }
            log_info("socks5-server", "peer #%d authenticated", peer_idx);

            /* ── Read connect request ── */
            char target_host[256]; size_t host_len; uint16_t target_port;
            if (recv_connect_req(client_fd, target_host, &host_len,
                                 &target_port, keys.dec_key) != 0) {
                log_error("socks5-server", "failed to receive connect request");
                secure_memzero(&keys, sizeof(keys));
                close(client_fd); _exit(1);
            }
            log_info("socks5-server", "connect → %s:%u", target_host, target_port);

            /* ── Connect to actual target ── */
            int target_fd = connect_to_host(target_host, (int)target_port, 0);
            if (target_fd < 0) {
                log_error("socks5-server", "cannot connect to %s:%u",
                          target_host, target_port);
                secure_memzero(&keys, sizeof(keys));
                close(client_fd); _exit(1);
            }

            /* ── Run tunnel (nonce starts at 2; 0=key_confirm, 1=connect_req) ── */
            tunnel_t tun;
            tunnel_init(&tun, target_fd, client_fd, keys.enc_key, keys.dec_key);
            tun.enc_nonce    = 2;
            tun.dec_nonce    = 2;
            tun.keepalive_sec = keepalive;
            

            int r = tunnel_run(&tun);
            secure_memzero(&keys, sizeof(keys));
            close(target_fd);
            close(client_fd);
            _exit(r == 0 ? 0 : 1);
        }
        g_active_conns++;
        close(client_fd);
    }
    while (waitpid(-1, NULL, 0) > 0) {}
    close(listen_fd);
    return 0;
}

/* ════════════════════════════════════════════════════════════════
 * SOCKS5 Client (local side — accepts SOCKS5 clients)
 * ════════════════════════════════════════════════════════════════ */

int mode_socks5_client(const char *remote_host, int remote_port,
                       int listen_port,
                       const uint8_t *psk, size_t psk_len,
                       int hs_timeout, int keepalive)
{
    int listen_fd = listen_on_port(listen_port);
    if (listen_fd < 0) return 1;

    log_info("socks5-client", "socks5://127.0.0.1:%d → %s:%d (auto-reconnect)",
             listen_port, remote_host, remote_port);

    while (g_running) {
        struct sockaddr_in la; socklen_t al = sizeof(la);
        int local_fd = accept(listen_fd, (struct sockaddr *)&la, &al);
        if (local_fd < 0) { if (errno == EINTR) continue; perror("accept"); continue; }
        g_active_conns++;

        /* ── SOCKS5 handshake: get target address ── */
        char target_host[256]; size_t host_len; uint16_t target_port;
        if (socks5_accept(local_fd, target_host, &host_len, &target_port) != 0) {
            log_warn("socks5-client", "SOCKS5 handshake failed");
            close(local_fd); g_active_conns--; continue;
        }
        log_info("socks5-client", "SOCKS5 CONNECT %s:%u", target_host, target_port);

        /* ── Reconnect loop (exponential backoff) ── */
        int retry_delay = 0;
        int connected   = 0;
        while (g_running && !connected) {
            int tunnel_fd = connect_to_host(remote_host, remote_port, 0);
            if (tunnel_fd < 0) {
                if (retry_delay == 0)
                    log_error("socks5-client", "cannot connect to %s:%d",
                              remote_host, remote_port);
                goto retry_sleep;
            }

            /* ── AEGIS handshake ── */
            session_keys_t keys;
            if (handshake_client(tunnel_fd, g_asym_priv, g_asym_peers[0],
                                 hs_timeout, &keys) == 0 &&
                handshake_key_confirm_client(tunnel_fd, &keys, hs_timeout) == 0) {

                /* ── Send connect request ── */
                if (send_connect_req(tunnel_fd, target_host, host_len,
                                     target_port, keys.enc_key) != 0) {
                    log_warn("socks5-client", "failed to send connect request");
                    close(tunnel_fd);
                    goto retry_sleep;
                }

                /* ── Run tunnel (nonce starts at 2) ── */
                tunnel_t tun;
                tunnel_init(&tun, local_fd, tunnel_fd,
                            keys.enc_key, keys.dec_key);
                tun.enc_nonce     = 2;   /* 0=key_confirm, 1=connect_req */
                tun.dec_nonce     = 2;
                tun.keepalive_sec = keepalive;
                

                retry_delay = 0;
                connected   = 1;
                int r = tunnel_run(&tun);
                secure_memzero(&keys, sizeof(keys));
                close(tunnel_fd);
                if (r != 0)
                    log_warn("socks5-client", "tunnel dropped");
            } else {
                log_warn("socks5-client", "handshake failed");
                close(tunnel_fd);
                goto retry_sleep;
            }

        retry_sleep:
            if (!g_running || connected) break;
            if (retry_delay == 0) retry_delay = 1;
            else if (retry_delay < 30) retry_delay *= 2;
            log_info("socks5-client", "retry in %ds...", retry_delay);
            sleep((unsigned)retry_delay);
        }

        g_active_conns--;
        close(local_fd);
    }
    close(listen_fd);
    return 0;
}
