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
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#define TUN_FWMARK       51820
#define MAX_TUN_CLIENTS     64
#define MAX_MULTIPATH         8   /* max parallel TCP connections */

/* ─── TUN client slot (parent-side) ────────────────────────────── */

typedef struct {
    int  local_fd;          /* parent end of socketpair */
    pid_t pid;              /* child process id */
    uint32_t peer_ip;       /* peer's TUN IP (network byte order) */
} tun_client_t;

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

/* ─── TUN Server (multi-client packet routing) ────────────────── */

/*
 * Architecture:
 *
 *   Parent:  owns tun_fd + listen_fd + local end of each socketpair.
 *            Runs a poll() loop that routes packets between the TUN
 *            device and per-client socketpairs based on IP header.
 *
 *   Child N: owns remote end of socketpair (plaintext_fd) + TCP
 *            encrypted_fd to client N.  Runs the standard tunnel
 *            event loop.  Sees a "virtual TUN" via the socketpair.
 *
 *   socketpair           tun_fd
 *   ┌─────────┐          ┌─────┐
 *   │ parent  │◄────────►│ TUN │
 *   │  poll() │          └─────┘
 *   │         │── sp[0] ──► child 1  ── TCP ──► client A (10.0.0.2)
 *   │         │── sp[0] ──► child 2  ── TCP ──► client B (10.0.0.3)
 *   └─────────┘
 */

/* Extract destination IPv4 address from an IP packet.
 * Returns the 32-bit address in host byte order, or 0 on error.
 * IP headers use network byte order (big-endian); ntohl() converts
 * to host byte order so the result can be compared with g_peer_tun_ips
 * (which is also stored in host byte order via bit-shift construction). */
static uint32_t ip_dst_addr(const uint8_t *pkt, size_t len)
{
    if (len < 20) return 0;
    uint8_t ver_ihl = pkt[0];
    if ((ver_ihl >> 4) != 4) return 0;           /* IPv4 only */
    int ihl = (int)(ver_ihl & 0x0f) * 4;
    if (ihl < 20 || (size_t)ihl > len) return 0;
    uint32_t addr;
    memcpy(&addr, pkt + 16, 4);                   /* dst at offset 16 (network order) */
    return ntohl(addr);                           /* convert to host byte order */
}

/* Find the client slot whose peer_ip matches the given address.
 * Uses round-robin when multiple slots share the same IP (multipath). */
static int find_client_by_ip(const tun_client_t *clients, int count, uint32_t ip)
{
    static int rr_counter = 0;
    int matches[MAX_TUN_CLIENTS];
    int m = 0;

    for (int i = 0; i < count; i++) {
        if (clients[i].local_fd != -1 && clients[i].peer_ip == ip)
            matches[m++] = i;
    }
    if (m == 0) return -1;
    rr_counter++;
    return matches[rr_counter % m];  /* round-robin across matches */
}

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

    int listen_fd = listen_on_port(listen_port);
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

/* ─── Multipath TUN Client ────────────────────────────────────── */
/*
 * Opens N parallel TCP connections to the server, each with its
 * own handshake and nonce space.  Outbound packets are distributed
 * across connections by a simple polynomial hash of the raw IP
 * packet, which preserves flow affinity (same flow → same path).
 */
static int tun_client_multipath(int tun_fd, const char *name,
                                 const char *host, int port, int peer_idx,
                                 int hs_timeout, int keepalive, int npaths,
                                 int first_fd, const session_keys_t *first_keys)
{
    int   tcp_fds[MAX_MULTIPATH];
    int   sp_fds[MAX_MULTIPATH][2];
    pid_t pids[MAX_MULTIPATH];
    int   opened = 0;

    /* ── Open N connections + handshake ── */
    for (int i = 0; i < npaths; i++) {
        session_keys_t keys;

        if (i == 0 && first_fd >= 0) {
            /* Reuse the already-authenticated first connection */
            tcp_fds[i] = first_fd;
            memcpy(&keys, first_keys, sizeof(keys));
        } else {
            /* Stagger connections to avoid server-side fork() storms */
            if (i > 1) usleep(80000);  /* 80ms between additional paths */
            tcp_fds[i] = connect_to_host(host, port, TUN_FWMARK);
            if (tcp_fds[i] < 0) {
                log_error("tun-client", "path %d/%d: cannot connect", i + 1, npaths);
                goto cleanup;
            }
            if (handshake_client(tcp_fds[i], g_asym_priv, g_asym_peers[peer_idx],
                                 hs_timeout, &keys) != 0 ||
                handshake_key_confirm_client(tcp_fds[i], &keys, hs_timeout) != 0) {
                log_warn("tun-client", "path %d/%d: handshake failed", i + 1, npaths);
                close(tcp_fds[i]); tcp_fds[i] = -1;
                goto cleanup;
            }
        }
        /* Create socketpair: sp[0]=parent, sp[1]=child */
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp_fds[i]) < 0) {
            close(tcp_fds[i]); tcp_fds[i] = -1;
            goto cleanup;
        }

        pid_t pid = fork();
        if (pid < 0) {
            close(sp_fds[i][0]); close(sp_fds[i][1]);
            close(tcp_fds[i]); tcp_fds[i] = -1;
            goto cleanup;
        }

        if (pid == 0) {
            /* Child: run tunnel over socketpair + TCP */
            close(sp_fds[i][0]);  /* parent end */
            close(tun_fd);
            for (int j = 0; j < i; j++) {
                close(sp_fds[j][0]); close(sp_fds[j][1]);
                if (tcp_fds[j] >= 0) close(tcp_fds[j]);
            }
            tunnel_t tun;
            tunnel_init(&tun, sp_fds[i][1], tcp_fds[i],
                        keys.enc_key, keys.dec_key);
            tun.keepalive_sec = keepalive;
            int r = tunnel_run(&tun);
            if (r != 0) fprintf(stderr, "[mp-child %d] tunnel_run returned %d (errno=%d)\n", i, r, errno);
            close(sp_fds[i][1]); close(tcp_fds[i]);
            _exit(r == 0 ? 0 : 1);
        }

        /* Parent: keep sp[0], discard sp[1] and tcp_fd (tcp is now owned by child) */
        close(sp_fds[i][1]);
        if (i > 0 || first_fd < 0) close(tcp_fds[i]);
        tcp_fds[i] = -1;
        pids[i]  = pid;
        opened++;
    }

    log_info("tun-client", "multipath: %d/%d paths established", opened, npaths);

    /* ── Parent event loop: TUN ↔ children ── */
    {
        struct pollfd fds[1 + MAX_MULTIPATH];
        while (g_running) {
            int nfds = 0;
            fds[nfds].fd = tun_fd; fds[nfds].events = POLLIN; nfds++;

            for (int i = 0; i < opened; i++) {
                if (sp_fds[i][0] >= 0) {
                    fds[nfds].fd     = sp_fds[i][0];
                    fds[nfds].events = POLLIN;
                    nfds++;
                }
            }

            int pr = poll(fds, (nfds_t)nfds, 500);
            if (pr < 0) { if (errno == EINTR) continue; break; }

            /* TUN → children: hash-routed */
            if (fds[0].revents & POLLIN) {
                for (;;) {
                    uint8_t pkt[FRAME_MAX_PAYLOAD];
                    ssize_t n = read(tun_fd, pkt, sizeof(pkt));
                    if (n < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                        goto mp_out;
                    }
                    if (n <= 0) goto mp_out;

                    /* Compute flow hash for path selection */
                    uint32_t h = 0;
                    for (ssize_t j = 0; j < n; j++)
                        h = h * 31 + pkt[j];
                    int pi = (int)(h % (uint32_t)opened);

                    if (sp_fds[pi][0] >= 0) {
                        size_t wr = 0;
                        while (wr < (size_t)n) {
                            ssize_t w = write(sp_fds[pi][0], pkt + wr,
                                             (size_t)n - wr);
                            if (w < 0) {
                                if (errno == EAGAIN || errno == EINTR) continue;
                                break;
                            }
                            wr += (size_t)w;
                        }
                    }
                }
            }

            /* Children → TUN */
            for (int i = 1; i < nfds; i++) {
                if (!(fds[i].revents & POLLIN)) continue;
                for (;;) {
                    uint8_t pkt[FRAME_MAX_PAYLOAD];
                    ssize_t n = read(fds[i].fd, pkt, sizeof(pkt));
                    if (n < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                        /* child died */
                        close(fds[i].fd);
                        for (int j = 0; j < opened; j++)
                            if (sp_fds[j][0] == fds[i].fd)
                                sp_fds[j][0] = -1;
                        break;
                    }
                    if (n == 0) {
                        close(fds[i].fd);
                        for (int j = 0; j < opened; j++)
                            if (sp_fds[j][0] == fds[i].fd)
                                sp_fds[j][0] = -1;
                        break;
                    }
                    size_t wr = 0;
                    while (wr < (size_t)n) {
                        ssize_t w = write(tun_fd, pkt + wr, (size_t)n - wr);
                        if (w < 0) {
                            if (errno == EAGAIN || errno == EINTR) continue;
                            break;
                        }
                        wr += (size_t)w;
                    }
                }
            }
        }
    }

mp_out:
    log_info("tun-client", "multipath stopped");

cleanup:
    /* Kill children and close remaining fds */
    for (int i = 0; i < opened; i++) {
        if (sp_fds[i][0] >= 0) close(sp_fds[i][0]);
        if (pids[i] > 0) kill(pids[i], SIGTERM);
    }
    while (waitpid(-1, NULL, 0) > 0) {}
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
        int tunnel_fd = connect_to_host(host, port, TUN_FWMARK);
        if (tunnel_fd < 0) {
            if (retry_delay == 0) log_error("tun-client", "cannot connect");
            peer_idx = (peer_idx + 1) % peer_count; goto retry;
        }

        session_keys_t keys;
        if (handshake_client(tunnel_fd, g_asym_priv, g_asym_peers[pi], hs_timeout, &keys) == 0 &&
            handshake_key_confirm_client(tunnel_fd, &keys, hs_timeout) == 0) {
            log_info("tun-client", "peer #%d authenticated", pi);

            if (g_tun_multipath > 1) {
                /* Multipath: reuse already-authenticated connection as path 0 */
                int mp_r = tun_client_multipath(tun_fd, name, host, port, pi,
                                                 hs_timeout, keepalive,
                                                 g_tun_multipath,
                                                 tunnel_fd, &keys);
                /* tunnel_fd is now owned by multipath child — do NOT close it here */
                if (mp_r == 0) break;
                log_warn("tun-client", "multipath dropped, reconnecting...");
            } else {
                tunnel_t tun; tunnel_init(&tun, tun_fd, tunnel_fd, keys.enc_key, keys.dec_key);

                int r = tunnel_run(&tun);
                secure_memzero(&keys, sizeof(keys));
                close(tunnel_fd);
                if (r == 0) break;
                log_warn("tun-client", "tunnel dropped, reconnecting...");
            }
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
