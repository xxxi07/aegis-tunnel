/*
 * mode_tun_udp.c — TUN VPN over UDP transport
 *
 * Eliminates TCP-over-TCP head-of-line blocking by using UDP
 * datagrams instead of TCP streams for data transport.
 *
 * Handshake reuses the existing TCP-based 3-DH code by using
 * connected UDP sockets (connect() on UDP → send/recv work).
 *
 * Data path:  each TUN IP packet → one AEGIS frame → one UDP
 * datagram.  Lost datagrams are handled by inner protocols —
 * guest TCP retransmissions cover any UDP loss.
 *
 * Usage:
 *   Server:  aegis-tunnel start tun -server -u
 *   Client:  aegis-tunnel start tun -client -u -r server:9000
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
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define UDP_MAX_DGRAM  65535
#define UDP_KEEPALIVE  25

/* ─── Shared TUN helpers (same as mode_tun.c) ─────────────────── */

static void tun_setup_routing(const char *name, const char *allowed_ips,
                               const char *nat_if, int is_server)
{
    if (is_server) {
        tun_enable_forwarding();
        if (allowed_ips && allowed_ips[0]) {
            tun_add_routes_multi(allowed_ips, name);
            tun_set_nat_multi(allowed_ips, nat_if);
        }
        tun_allow_forward(name);
    }
}

static void tun_run_postup(const char *script, const char *name)
{
    if (script && script[0]) { tun_exec_script(script, name); }
}

static void tun_run_postdown(const char *script, const char *name)
{
    if (script && script[0]) { tun_exec_script(script, name); }
}

/* ════════════════════════════════════════════════════════════════
 * TUN UDP Server
 * ════════════════════════════════════════════════════════════════ */

int mode_tun_udp_server(int listen_port,
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
        if (!strcmp(tun_route, "0.0.0.0/0") || !strcmp(tun_route, "::/0"))
            tun_add_full_tunnel(name);
        else tun_add_route(tun_route, name);
    }
    tun_setup_routing(name, tun_route, tun_nat_if, 1 /* server */);
    tun_run_postup(postup, name);

    int udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_fd < 0) { close(tun_fd); return 1; }
    {
        struct sockaddr_in sa; memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = INADDR_ANY;
        sa.sin_port = htons((uint16_t)listen_port);
        if (bind(udp_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
            perror("udp bind"); close(udp_fd); close(tun_fd); return 1;
        }
    }

    log_info("udp-server", "%s (%s/%s) udp:%d route=%s",
             name, tun_ip && tun_ip[0] ? tun_ip : "dhcp", tun_netmask,
             listen_port, tun_route ? tun_route : "(none)");

    (void)psk; (void)psk_len;

    while (g_running) {
        /* Wait for handshake init from any client */
        uint8_t hdr[64];
        struct sockaddr_in ca; socklen_t alen = sizeof(ca);
        ssize_t nr = recvfrom(udp_fd, hdr, sizeof(hdr), 0,
                              (struct sockaddr *)&ca, &alen);
        if (nr < 0) { if (errno == EINTR) continue; break; }
        if (nr < 40 || hdr[0] != FRAME_HANDSHAKE) continue;

        /* Create connected UDP socket for this client */
        int cfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (cfd < 0) continue;
        if (connect(cfd, (struct sockaddr *)&ca, sizeof(ca)) < 0) {
            close(cfd); continue;
        }

        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ca.sin_addr, ip, sizeof(ip));
        log_info("udp-server", "handshake from %s:%d", ip, ntohs(ca.sin_port));

        /* Re-inject the first datagram into the connected socket */
        if (send(cfd, hdr, (size_t)nr, 0) < 0) { close(cfd); continue; }

        /* Fork: child handles this client */
        pid_t pid = fork();
        if (pid < 0) { close(cfd); continue; }

        if (pid == 0) {
            close(udp_fd);
            signal(SIGCHLD, SIG_DFL);

            /* Handshake using connected UDP (reuses TCP handshake code) */
            session_keys_t keys;
            if (try_handshake_server(cfd, &keys, hs_timeout) < 0) {
                log_warn("udp-server", "handshake failed");
                close(cfd); _exit(1);
            }
            if (handshake_key_confirm_server(cfd, &keys, hs_timeout) != 0) {
                secure_memzero(&keys, sizeof(keys));
                close(cfd); _exit(1);
            }
            {
                uint8_t kw[FRAME_HEADER_LEN + AEGIS_TAG_LEN];
                if (recv_all(cfd, kw, sizeof(kw)) == 0) {
                    uint8_t ty, fl, dum[1]; size_t dl;
                    if (frame_parse(kw, sizeof(kw), &ty, &fl, dum, &dl, 0, keys.dec_key) == 0
                        && ty == FRAME_KEYCONFIRM) {
                        /* Client KEY_CONFIRM OK */
                    }
                }
            }

            /* Data loop: TUN ↔ UDP */
            uint64_t enc_nonce = 1, dec_nonce = 1;
            int64_t last_ka = (int64_t)time(NULL);
            struct pollfd fds[2];
            fds[0].fd = tun_fd; fds[0].events = POLLIN;
            fds[1].fd = cfd;    fds[1].events = POLLIN;

            while (g_running) {
                fds[0].revents = 0; fds[1].revents = 0;
                int pr = poll(fds, 2, keepalive > 0 ? keepalive * 1000 : 500);
                if (pr < 0) { if (errno == EINTR) continue; break; }

                /* TUN → UDP */
                if (fds[0].revents & POLLIN) {
                    for (;;) {
                        uint8_t pkt[FRAME_MAX_PAYLOAD];
                        ssize_t n = read(tun_fd, pkt, sizeof(pkt));
                        if (n < 0) { if (errno == EAGAIN || errno == EWOULDBLOCK) break; goto out; }
                        if (n <= 0) goto out;

                        uint8_t wb[FRAME_MAX_WIRE]; size_t wl;
                        if (frame_build(wb, &wl, FRAME_DATA, 0, pkt, (size_t)n, enc_nonce, keys.enc_key) == 0) {
                            enc_nonce++;
                            send(cfd, wb, wl, 0);
                        }
                    }
                }

                /* UDP → TUN */
                if (fds[1].revents & POLLIN) {
                    for (;;) {
                        uint8_t wb[UDP_MAX_DGRAM];
                        ssize_t n = recv(cfd, wb, sizeof(wb), 0);
                        if (n < 0) { if (errno == EAGAIN || errno == EWOULDBLOCK) break; goto out; }
                        if (n == 0) goto out;

                        uint8_t ty, fl, pkt[FRAME_MAX_PAYLOAD]; size_t pl;
                        if (frame_parse(wb, (size_t)n, &ty, &fl, pkt, &pl, dec_nonce, keys.dec_key) == 0) {
                            dec_nonce++;
                            if (ty == FRAME_DATA && pl > 0) {
                                size_t wr = 0;
                                while (wr < pl) {
                                    ssize_t w = write(tun_fd, pkt + wr, pl - wr);
                                    if (w < 0) { if (errno == EAGAIN || errno == EINTR) continue; break; }
                                    wr += (size_t)w;
                                }
                            }
                        }
                        if (dec_nonce >= UINT64_C(0xFFFFFFFFFFFFFFF0) - 10000) break; /* would need re-key */
                    }
                }

                /* Keepalive */
                {
                    int64_t now = (int64_t)time(NULL);
                    if (keepalive > 0 && now - last_ka >= keepalive) {
                        uint8_t kw[FRAME_MAX_WIRE]; size_t kwl;
                        if (frame_build(kw, &kwl, FRAME_KEEPALIVE, 0, NULL, 0, enc_nonce, keys.enc_key) == 0) {
                            enc_nonce++;
                            send(cfd, kw, kwl, 0);
                        }
                        last_ka = now;
                    }
                }
            }
        out:
            secure_memzero(&keys, sizeof(keys));
            close(cfd); close(tun_fd);
            _exit(0);
        }
        close(cfd);
        while (waitpid(-1, NULL, WNOHANG) > 0) {}
    }

    tun_run_postdown(postdown, name);
    tun_teardown(name, 1);
    close(udp_fd); close(tun_fd);
    return 0;
}

/* ════════════════════════════════════════════════════════════════
 * TUN UDP Client
 * ════════════════════════════════════════════════════════════════ */

int mode_tun_udp_client(const char *remote_host, int remote_port,
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
    if (tun_route && tun_route[0]) {
        if (!strcmp(tun_route, "0.0.0.0/0") || !strcmp(tun_route, "::/0")) {
            tun_add_full_tunnel(name);
            tun_set_fwmark_rule(51820);
        } else tun_add_route(tun_route, name);
    }
    tun_run_postup(postup, name);
    (void)psk; (void)psk_len;

    log_info("udp-client", "%s (%s/%s) → %s:%d",
             name, tun_ip && tun_ip[0] ? tun_ip : "dhcp", tun_netmask,
             remote_host, remote_port);

    /* Reconnect loop */
    while (g_running) {
        /* Create UDP socket + connect to server */
        int udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (udp_fd < 0) { sleep(1); continue; }

        /* Resolve server address */
        struct addrinfo hints, *res;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;
        char ps[16]; snprintf(ps, sizeof(ps), "%d", remote_port);
        if (getaddrinfo(remote_host, ps, &hints, &res) != 0 || !res) {
            close(udp_fd); sleep(2); continue;
        }
        if (connect(udp_fd, res->ai_addr, res->ai_addrlen) < 0) {
            freeaddrinfo(res); close(udp_fd); sleep(2); continue;
        }
        freeaddrinfo(res);

        /* Handshake over connected UDP */
        session_keys_t keys;
        if (handshake_client(udp_fd, g_asym_priv, g_asym_peers[0], hs_timeout, &keys) != 0 ||
            handshake_key_confirm_client(udp_fd, &keys, hs_timeout) != 0) {
            log_warn("udp-client", "handshake failed");
            close(udp_fd); sleep(2); continue;
        }

        log_info("udp-client", "connected");

        /* Data loop */
        uint64_t enc_nonce = 1, dec_nonce = 1;
        int64_t last_ka = (int64_t)time(NULL);
        struct pollfd fds[2];
        fds[0].fd = tun_fd; fds[0].events = POLLIN;
        fds[1].fd = udp_fd; fds[1].events = POLLIN;

        while (g_running) {
            fds[0].revents = 0; fds[1].revents = 0;
            int pr = poll(fds, 2, keepalive > 0 ? keepalive * 1000 : 500);
            if (pr < 0) { if (errno == EINTR) continue; break; }

            if (fds[0].revents & POLLIN) {
                for (;;) {
                    uint8_t pkt[FRAME_MAX_PAYLOAD];
                    ssize_t n = read(tun_fd, pkt, sizeof(pkt));
                    if (n < 0) { if (errno == EAGAIN || errno == EWOULDBLOCK) break; goto disconnect; }
                    if (n <= 0) goto disconnect;
                    uint8_t wb[FRAME_MAX_WIRE]; size_t wl;
                    if (frame_build(wb, &wl, FRAME_DATA, 0, pkt, (size_t)n, enc_nonce, keys.enc_key) == 0) {
                        enc_nonce++;
                        send(udp_fd, wb, wl, 0);
                    }
                }
            }

            if (fds[1].revents & POLLIN) {
                for (;;) {
                    uint8_t wb[UDP_MAX_DGRAM];
                    ssize_t n = recv(udp_fd, wb, sizeof(wb), 0);
                    if (n < 0) { if (errno == EAGAIN || errno == EWOULDBLOCK) break; goto disconnect; }
                    if (n == 0) goto disconnect;
                    uint8_t ty, fl, pkt[FRAME_MAX_PAYLOAD]; size_t pl;
                    if (frame_parse(wb, (size_t)n, &ty, &fl, pkt, &pl, dec_nonce, keys.dec_key) == 0) {
                        dec_nonce++;
                        if (ty == FRAME_DATA && pl > 0) {
                            size_t wr = 0;
                            while (wr < pl) {
                                ssize_t w = write(tun_fd, pkt + wr, pl - wr);
                                if (w < 0) { if (errno == EAGAIN || errno == EINTR) continue; break; }
                                wr += (size_t)w;
                            }
                        }
                    }
                }
            }

            {
                int64_t now = (int64_t)time(NULL);
                if (keepalive > 0 && now - last_ka >= keepalive) {
                    uint8_t kw[FRAME_MAX_WIRE]; size_t kwl;
                    if (frame_build(kw, &kwl, FRAME_KEEPALIVE, 0, NULL, 0, enc_nonce, keys.enc_key) == 0) {
                        enc_nonce++;
                        send(udp_fd, kw, kwl, 0);
                    }
                    last_ka = now;
                }
            }
        }
    disconnect:
        secure_memzero(&keys, sizeof(keys));
        close(udp_fd);
        log_info("udp-client", "disconnected, reconnecting in 2s...");
        sleep(2);
    }

    tun_run_postdown(postdown, name);
    tun_teardown(name, 0);
    close(tun_fd);
    return 0;
}
