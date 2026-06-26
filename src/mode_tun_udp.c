/*
 * mode_tun_udp.c — TUN VPN over UDP transport
 *
 * Eliminates TCP-over-TCP head-of-line blocking by using UDP
 * datagrams instead of TCP streams.
 *
 * Handshake: custom UDP implementation (cannot reuse TCP handshake
 * because TCP uses stream-oriented recv_all in multiple steps, which
 * would truncate UDP datagrams).
 *
 * Data path: each TUN IP packet → one AEGIS frame → one UDP datagram.
 *
 * Usage:
 *   Server:  aegis-tunnel start tun -server -U
 *   Client:  aegis-tunnel start tun -client -U -r server:9000
 */

#include "main.h"
#include "mode_common.h"
#include "protocol/ecdh.h"
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
#include <openssl/evp.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void sha256_h(uint8_t out[32], const uint8_t *in, size_t len) {
    EVP_MD_CTX *c = EVP_MD_CTX_new(); unsigned int o = 0;
    EVP_DigestInit_ex(c, EVP_sha256(), NULL);
    EVP_DigestUpdate(c, in, len);
    EVP_DigestFinal_ex(c, out, &o);
    EVP_MD_CTX_free(c);
}

#define UDP_MAX_DGRAM  65535
#define UDP_KEEPALIVE  25

/* ─── Shared TUN helpers ──────────────────────────────────────── */

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
static void tun_run_postup(const char *script, const char *name) {
    if (script && script[0]) tun_exec_script(script, name);
}
static void tun_run_postdown(const char *script, const char *name) {
    if (script && script[0]) tun_exec_script(script, name);
}

/* ─── UDP I/O helpers ─────────────────────────────────────────── */

static int udp_send(int fd, const uint8_t *data, size_t len)
{
    ssize_t n = send(fd, data, len, 0);
    return (n == (ssize_t)len) ? 0 : -1;
}

/* sendto variant — uses explicit destination address (keeps source port) */
static int udp_sendto(int fd, const uint8_t *data, size_t len,
                       const struct sockaddr_in *dest)
{
    ssize_t n = sendto(fd, data, len, 0,
                       (const struct sockaddr *)dest, sizeof(*dest));
    return (n == (ssize_t)len) ? 0 : -1;
}

static int udp_recv(int fd, uint8_t *buf, size_t maxlen)
{
    ssize_t n = recv(fd, buf, maxlen, 0);
    if (n < 0) return -1;
    return (int)n;
}

/*
 * Receive a datagram from a specific peer.  Filters by source
 * address; datagrams from other peers are silently discarded
 * (returns 0 so the caller can retry / poll again).
 * Used as a fallback when SO_REUSEPORT is unavailable.
 */
static int udp_recv_peer(int fd, uint8_t *buf, size_t maxlen,
                          const struct sockaddr_in *peer)
{
    struct sockaddr_in src;
    socklen_t srclen = sizeof(src);
    ssize_t n = recvfrom(fd, buf, maxlen, 0,
                         (struct sockaddr *)&src, &srclen);
    if (n < 0) return -1;
    if (src.sin_addr.s_addr != peer->sin_addr.s_addr ||
        src.sin_port != peer->sin_port)
        return 0;  /* not our client — silently skip */
    return (int)n;
}

/* ─── UDP handshake: complete datagram based ──────────────────── */

#define UDP_HS_DGRAM  60   /* wire size of one handshake message */

/*
 * Build a HANDSHAKE init/resp datagram (60 bytes on wire).
 *   payload = [eph_pub(32)][timestamp(8)] = 40 bytes
 *   encrypted with the given key → [header(4)][ct(40)][tag(16)] = 60
 */
/*
 * Build a HANDSHAKE init/resp datagram (60 bytes on wire).
 *
 * Matches the TCP handshake wire format (handshake.c asym_send):
 *   [type:1][flags:1][len:2 BE][eph_pub:32 CLEAR][enc_ts:8][tag:16]
 *
 * The ephemeral public key is sent in the clear (bytes 4..35).
 * Only the 8-byte timestamp is encrypted.  The receiver extracts
 * the plaintext eph_pub to compute the decryption key before
 * attempting to decrypt the timestamp — this works because the
 * eph_pub is part of the AD, and AEGIS authenticates the AD.
 */
static int udp_hs_build(uint8_t out[UDP_HS_DGRAM],
                         const uint8_t eph_pub[32], int64_t ts,
                         const uint8_t key[16])
{
    /* Header */
    out[0] = FRAME_HANDSHAKE;   /* type */
    out[1] = FLAG_NONE;         /* flags */
    out[2] = 0;                 /* length hi — 8 bytes of encrypted timestamp */
    out[3] = 8;                 /* length lo */

    /* eph_pub in the clear at bytes 4..35 (same as TCP handshake) */
    memcpy(out + 4, eph_pub, 32);

    /* AD = header(4) || eph_pub_plaintext(32) = 36 bytes */
    uint8_t ad[36];
    memcpy(ad, out, 4);
    memcpy(ad + 4, eph_pub, 32);

    /* Encrypt timestamp only (8 bytes at offset 36, tag at offset 44) */
    uint8_t tsb[8];
    uint64_t tb = (uint64_t)ts;
    for (int i = 0; i < 8; i++) tsb[7 - i] = (uint8_t)(tb >> (i * 8));

    uint8_t n[16] = {0};
    aegis_encrypt(out + 36, out + 44, tsb, 8, ad, 36, n, key);
    return 0;
}

/*
 * Parse a HANDSHAKE init/resp datagram.
 *
 * Reads the plaintext eph_pub from bytes 4..35, builds the AD,
 * then decrypts the timestamp at bytes 36..43 using the given key.
 * On success fills eph_pub[32] and *ts (timestamp).
 */
static int udp_hs_parse(const uint8_t dgram[UDP_HS_DGRAM],
                         uint8_t eph_pub[32], int64_t *ts,
                         const uint8_t key[16])
{
    if (dgram[0] != FRAME_HANDSHAKE) return -1;

    /* eph_pub is plaintext at bytes 4..35 */
    memcpy(eph_pub, dgram + 4, 32);

    /* AD = header(4) || eph_pub_plaintext(32) = 36 bytes */
    uint8_t ad[36];
    memcpy(ad, dgram, 4);
    memcpy(ad + 4, eph_pub, 32);

    /* Decrypt timestamp (8 bytes of ciphertext at offset 36, tag at 44) */
    uint8_t tsb[8], n[16] = {0};
    if (aegis_decrypt(tsb, dgram + 36, 8, ad, 36, n, key,
                      dgram + 44) != 0) return -1;

    /* Parse timestamp from big-endian */
    uint64_t tb = 0;
    for (int i = 0; i < 8; i++) tb = (tb << 8) | tsb[i];
    *ts = (int64_t)tb;
    return 0;
}

/* ─── Full UDP handshake (server side) ────────────────────────── */

/*
 * Server-side UDP handshake.
 *
 * If first_dgram is non-NULL, it contains the already-read HANDSHAKE_INIT
 * datagram (passed from the parent via a pipe, since the parent consumes
 * it from the shared UDP socket via recvfrom to learn the client address).
 * Otherwise the function reads the first datagram from fd directly.
 */
static int udp_handshake_server(int fd, session_keys_t *keys, int timeout_ms,
                                 const uint8_t *first_dgram, size_t first_len)
{
    (void)timeout_ms;
    uint8_t dgram[UDP_HS_DGRAM];

    /* 1. Get HANDSHAKE_INIT (either pre-read or from socket) */
    if (first_dgram) {
        if (first_len < UDP_HS_DGRAM) return -1;
        memcpy(dgram, first_dgram, UDP_HS_DGRAM);
    } else {
        if (udp_recv(fd, dgram, sizeof(dgram)) < UDP_HS_DGRAM) return -1;
    }

    /* 2. Extract initiator's ephemeral pubkey (plaintext part of header) */
    uint8_t iepk[32];
    memcpy(iepk, dgram + 4, 32);

    /* 3. Try each known peer key */
    for (int pi = 0; pi < g_peer_count; pi++) {
        /* Compute init_key = SHA256(X25519(sk,iepk) || X25519(sk,pk) || "init") */
        uint8_t ee[32], es_init[32], ik[16];
        ecdh_derive(ee, g_asym_priv, iepk);
        ecdh_derive(es_init, g_asym_priv, g_asym_peers[pi]);
        uint8_t b[68]; memcpy(b, ee, 32); memcpy(b + 32, es_init, 32);
        memcpy(b + 64, "init", 4);
        uint8_t h[32]; sha256_h(h, b, 68); memcpy(ik, h, 16);

        /* Try decrypting datagram with this init_key */
        int64_t its;
        if (udp_hs_parse(dgram, iepk, &its, ik) != 0)
            continue;  /* wrong peer key */

        /* Verify timestamp */
        int64_t now = timestamp_now();
        if (now < 0 || (now > its ? now - its : its - now) > 60)
            continue;

        log_info("udp-server", "peer #%d key matched", pi);

        /* 4. Generate our ephemeral keypair */
        uint8_t epk[32], ek[32];
        if (ecdh_keygen(epk, ek) != 0) { log_warn("udp-server", "keygen failed"); continue; }

        /* 5. Compute shared secret (3-DH: ee, es, se) */
        uint8_t es[32], se[32];
        ecdh_derive(ee, g_asym_priv, iepk);                   /* our_sk × their_eph */
        ecdh_derive(es, g_asym_priv, g_asym_peers[pi]);       /* our_sk × their_sk  */
        ecdh_derive(se, ek, g_asym_peers[pi]);                /* our_eph × their_sk */
        uint8_t sb[102]; memcpy(sb, ee, 32);
        memcpy(sb + 32, es, 32); memcpy(sb + 64, se, 32);
        memcpy(sb + 96, "shared", 6);
        uint8_t sh[32]; sha256_h(sh, sb, 102);

        /* Session keys: SHA256(sh(32) || "session"(7)) = 39 bytes */
        {
            uint8_t sk[39];
            memcpy(sk, sh, 32);
            memcpy(sk + 32, "session", 7);
            sha256_h(h, sk, 39);
        }
        memcpy(keys->dec_key, h, 16);       /* server dec = client enc */
        memcpy(keys->enc_key, h + 16, 16);  /* server enc = client dec */

        /* 6. Send HANDSHAKE_RESP */
        {
            uint8_t rk[16], rkb[36];
            memcpy(rkb, sh, 32); memcpy(rkb + 32, "resp", 4);
            sha256_h(h, rkb, 36); memcpy(rk, h, 16);
            uint8_t rdgram[UDP_HS_DGRAM];
            udp_hs_build(rdgram, epk, timestamp_now(), rk);
            if (udp_send(fd, rdgram, sizeof(rdgram)) != 0) {
                log_warn("udp-server", "failed to send RESP (errno=%d)", errno);
                continue;
            }
        }
        log_info("udp-server", "RESP sent");

        /* 7. Send KEY_CONFIRM */
        {
            uint8_t kw[FRAME_MAX_WIRE]; size_t kwl;
            frame_build(kw, &kwl, FRAME_KEYCONFIRM, 0, NULL, 0, 0, keys->enc_key);
            if (udp_send(fd, kw, kwl) != 0) {
                log_warn("udp-server", "failed to send KEY_CONFIRM (errno=%d)", errno);
                continue;
            }
        }
        log_info("udp-server", "KEY_CONFIRM sent, waiting for client...");

        /* 8. Receive client KEY_CONFIRM */
        {
            uint8_t ckw[FRAME_HEADER_LEN + AEGIS_TAG_LEN];
            int nr;
            nr = udp_recv(fd, ckw, sizeof(ckw));
            log_info("udp-server", "recv returned %d (errno=%d)", nr, errno);
            if (nr >= (int)sizeof(ckw)) {
                uint8_t ty, fl, dum[1]; size_t dl;
                if (frame_parse(ckw, sizeof(ckw), &ty, &fl, dum, &dl,
                                0, keys->dec_key) == 0 && ty == FRAME_KEYCONFIRM) {
                    secure_memzero(ee, 32); secure_memzero(es_init, 32);
                    secure_memzero(ek, 32); secure_memzero(sh, 32);
                    log_info("udp-server", "peer #%d authenticated", pi);
                    return 0;
                }
                log_warn("udp-server", "KEY_CONFIRM parse failed (ty=%d)", ty);
            }
        }
    }
    log_warn("udp-server", "no matching peer key (tried %d)", g_peer_count);
    return -1;
}

/* ─── Full UDP handshake (client side) ────────────────────────── */

static int udp_handshake_client(int fd, int peer_idx,
                                 session_keys_t *keys, int timeout_ms)
{
    (void)timeout_ms;
    uint8_t dgram[UDP_HS_DGRAM];
    uint8_t h[32];

    /* 1. Generate ephemeral keypair */
    uint8_t ek[32], epk[32];
    if (ecdh_keygen(epk, ek) != 0) return -1;

    /* 2. Compute init_key: SHA256(X25519(eph, pk) || X25519(sk, pk) || "init") */
    uint8_t ee_init[32], es_init[32], ik[16];
    ecdh_derive(ee_init, ek, g_asym_peers[peer_idx]);            /* eph_sk × static_pk */
    ecdh_derive(es_init, g_asym_priv, g_asym_peers[peer_idx]);   /* static_sk × static_pk */
    uint8_t b[68]; memcpy(b, ee_init, 32); memcpy(b + 32, es_init, 32);
    memcpy(b + 64, "init", 4);
    sha256_h(h, b, 68); memcpy(ik, h, 16);

    /* 3. Send HANDSHAKE_INIT */
    udp_hs_build(dgram, epk, timestamp_now(), ik);
    if (udp_send(fd, dgram, sizeof(dgram)) != 0) {
        log_warn("udp-client", "failed to send INIT (errno=%d)", errno);
        return -1;
    }
    log_info("udp-client", "INIT sent, waiting for RESP...");

    /* 4. Receive HANDSHAKE_RESP (one complete datagram) */
    {
        int nr = udp_recv(fd, dgram, sizeof(dgram));
        log_info("udp-client", "recv RESP returned %d (errno=%d)", nr, errno);
        if (nr < UDP_HS_DGRAM) {
            log_warn("udp-client", "short RESP: got %d, expected %d", nr, UDP_HS_DGRAM);
            return -1;
        }
    }

    /* 5. Compute shared secret (needs repk from response, which is in the AD) */
    uint8_t repk[32];
    memcpy(repk, dgram + 4, 32);  /* server's ephemeral pubkey (plaintext in AD) */

    {
        uint8_t ee[32], es[32], se[32];
        /* 3-DH must match server's computation (handshake.c asym_shared):
         *   ee = X25519(eph_c, static_s)     ← was incorrectly eph_c × eph_s
         *   es = X25519(static_c, static_s)
         *   se = X25519(static_c, eph_s) */
        ecdh_derive(ee, ek, g_asym_peers[peer_idx]);             /* eph_sk × static_pk */
        ecdh_derive(es, g_asym_priv, g_asym_peers[peer_idx]);    /* static_sk × static_pk */
        ecdh_derive(se, g_asym_priv, repk);                      /* static_sk × eph_pk */

        uint8_t sb[102]; memcpy(sb, ee, 32); memcpy(sb + 32, es, 32);
        memcpy(sb + 64, se, 32); memcpy(sb + 96, "shared", 6);
        uint8_t sh[32]; sha256_h(sh, sb, 102);

        /* 6. Derive resp_key and decrypt/verify the response */
        uint8_t rk_buf[36], rk[16];
        memcpy(rk_buf, sh, 32); memcpy(rk_buf + 32, "resp", 4);
        sha256_h(h, rk_buf, 36); memcpy(rk, h, 16);

        int64_t rts;
        if (udp_hs_parse(dgram, repk, &rts, rk) != 0) {
            log_warn("udp-client", "RESP parse/auth failed");
            secure_memzero(ee, 32); secure_memzero(es, 32);
            secure_memzero(se, 32); secure_memzero(sh, 32);
            return -1;
        }

        int64_t now = timestamp_now();
        if (now < 0 || (now > rts ? now - rts : rts - now) > 60) {
            log_warn("udp-client", "RESP timestamp out of window");
            secure_memzero(ee, 32); secure_memzero(es, 32);
            secure_memzero(se, 32); secure_memzero(sh, 32);
            return -1;
        }

        /* 7. Session keys: SHA256(sh(32) || "session"(7)) = 39 bytes */
        {
            uint8_t sk[39];
            memcpy(sk, sh, 32);
            memcpy(sk + 32, "session", 7);
            sha256_h(h, sk, 39);
        }
        memcpy(keys->enc_key, h, 16);
        memcpy(keys->dec_key, h + 16, 16);

        secure_memzero(ee, 32); secure_memzero(es, 32);
        secure_memzero(se, 32); secure_memzero(sh, 32);
    }

    log_info("udp-client", "RESP verified, waiting for server KEY_CONFIRM...");

    /* 8. Receive server KEY_CONFIRM */
    {
        uint8_t kw[FRAME_HEADER_LEN + AEGIS_TAG_LEN];
        int nr = udp_recv(fd, kw, sizeof(kw));
        log_info("udp-client", "recv KEY_CONFIRM returned %d (errno=%d)", nr, errno);
        if (nr < (int)sizeof(kw)) {
            log_warn("udp-client", "short KEY_CONFIRM: got %d, expected %zu", nr, sizeof(kw));
            return -1;
        }
        uint8_t ty, fl, dum[1]; size_t dl;
        if (frame_parse(kw, sizeof(kw), &ty, &fl, dum, &dl,
                        0, keys->dec_key) != 0 || ty != FRAME_KEYCONFIRM) {
            log_warn("udp-client", "KEY_CONFIRM parse failed (ty=%d)", ty);
            return -1;
        }
    }

    /* 9. Send KEY_CONFIRM */
    {
        uint8_t kw[FRAME_MAX_WIRE]; size_t kwl;
        frame_build(kw, &kwl, FRAME_KEYCONFIRM, 0, NULL, 0, 0, keys->enc_key);
        if (udp_send(fd, kw, kwl) != 0) {
            log_warn("udp-client", "failed to send KEY_CONFIRM (errno=%d)", errno);
            return -1;
        }
    }

    log_info("udp-client", "handshake complete");
    return 0;
}

/* ════════════════════════════════════════════════════════════════
 * TUN UDP Server
 * ════════════════════════════════════════════════════════════════ */

/*
 * ═══════════════════════════════════════════════════════════════════
 * TUN UDP Server — WireGuard-style single-process poll loop
 *
 * Architecture (WireGuard-like):
 *   - Single UDP socket bound to listen_port.
 *   - No fork(), no connected sockets, no SO_REUSEPORT.
 *   - recvfrom() / sendto() for all I/O.
 *   - Per-client session table keyed by (IP, port) for data frames.
 *   - Handshake processed synchronously in the main loop.
 *
 * Poll set:  [ udp_fd, tun_fd ]
 *
 *   udp_fd readable → recvfrom → HANDSHAKE? → process handshake
 *                               → DATA?      → lookup session, decrypt → TUN
 *   tun_fd readable → read IP pkt → route by dst IP → encrypt → sendto
 * ═══════════════════════════════════════════════════════════════════
 */

#define UDP_MAX_CLIENTS 64

typedef struct {
    struct sockaddr_in addr;     /* client's last-known address */
    uint8_t  enc_key[16];       /* server→client encrypt key */
    uint8_t  dec_key[16];       /* client→server decrypt key */
    uint32_t tun_ip;            /* peer's TUN IP (host byte order) */
    int64_t  last_seen;         /* last activity timestamp */
    int      active;            /* 1 = handshake complete, session live */
} udp_session_t;

/* Extract destination IPv4 address from an IP packet (host byte order). */
static uint32_t ip_dst_addr(const uint8_t *pkt, size_t len)
{
    if (len < 20) return 0;
    if ((pkt[0] >> 4) != 4) return 0;
    int ihl = (int)(pkt[0] & 0x0f) * 4;
    if (ihl < 20 || (size_t)ihl > len) return 0;
    uint32_t addr;
    memcpy(&addr, pkt + 16, 4);
    return ntohl(addr);
}

/* Find session by client IP address (port ignored — NAT may rebind). */
static int session_find(const udp_session_t *sessions, int count,
                         const struct sockaddr_in *addr)
{
    for (int i = 0; i < count; i++) {
        if (!sessions[i].active) continue;
        if (sessions[i].addr.sin_addr.s_addr == addr->sin_addr.s_addr)
            return i;
    }
    return -1;
}

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

    /* Single UDP socket — WireGuard uses exactly one. */
    int udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_fd < 0) { close(tun_fd); return 1; }
    {
        int reuse = 1;
        setsockopt(udp_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
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

    /* ── Session table ── */
    udp_session_t sessions[UDP_MAX_CLIENTS];
    int           session_count = 0;
    memset(sessions, 0, sizeof(sessions));

    /* ── Main poll loop ── */
    while (g_running) {
        struct pollfd fds[2];
        fds[0].fd = udp_fd;  fds[0].events = POLLIN; fds[0].revents = 0;
        fds[1].fd = tun_fd;  fds[1].events = POLLIN; fds[1].revents = 0;

        int pr = poll(fds, 2, keepalive > 0 ? keepalive * 1000 : 500);
        if (pr < 0) { if (errno == EINTR) continue; break; }

        /* ── UDP → TUN ── */
        if (fds[0].revents & POLLIN) {
            for (;;) {
                if (!g_running) break;
                uint8_t buf[UDP_MAX_DGRAM];
                struct sockaddr_in sender;
                socklen_t slen = sizeof(sender);
                ssize_t nr = recvfrom(udp_fd, buf, sizeof(buf), 0,
                                      (struct sockaddr *)&sender, &slen);
                if (nr < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                    continue;  /* drop malformed */
                }

                /* ── Handshake ── */
                if (nr >= UDP_HS_DGRAM && buf[0] == FRAME_HANDSHAKE) {
                    char rip[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &sender.sin_addr, rip, sizeof(rip));
                    if (handshake_rate_check(rip, (int64_t)time(NULL)) < 0)
                        continue;

                    log_info("udp-server", "handshake from %s:%d",
                             rip, ntohs(sender.sin_port));

                    /* Process handshake synchronously (like WireGuard).
                     * This blocks the poll loop for ~1 RTT, but handshakes
                     * are infrequent and complete in < 100 ms. */
                    {
                        session_keys_t keys;
                        int ok = 0, peer_matched = -1;

                        /* === Server-side handshake inline === */
                        {
                            uint8_t dgram[UDP_HS_DGRAM];
                            memcpy(dgram, buf, UDP_HS_DGRAM);
                            uint8_t iepk[32];
                            memcpy(iepk, dgram + 4, 32);
                            uint8_t h[32];

                            for (int pi = 0; pi < g_peer_count; pi++) {
                                uint8_t ee[32], es_init[32], ik[16];
                                ecdh_derive(ee, g_asym_priv, iepk);
                                ecdh_derive(es_init, g_asym_priv, g_asym_peers[pi]);
                                {
                                    uint8_t b[68]; memcpy(b, ee, 32);
                                    memcpy(b + 32, es_init, 32);
                                    memcpy(b + 64, "init", 4);
                                    sha256_h(h, b, 68); memcpy(ik, h, 16);
                                }

                                int64_t its;
                                if (udp_hs_parse(dgram, iepk, &its, ik) != 0)
                                    continue;
                                int64_t now = timestamp_now();
                                if (now < 0 || (now > its ? now - its : its - now) > 60)
                                    continue;

                                log_info("udp-server", "peer #%d key matched", pi);
                                peer_matched = pi;

                                uint8_t epk[32], ek[32];
                                if (ecdh_keygen(epk, ek) != 0) continue;

                                /* 3-DH shared secret */
                                uint8_t es[32], se[32];
                                ecdh_derive(ee, g_asym_priv, iepk);
                                ecdh_derive(es, g_asym_priv, g_asym_peers[pi]);
                                ecdh_derive(se, ek, g_asym_peers[pi]);
                                uint8_t sh[32];
                                {
                                    uint8_t sb[102]; memcpy(sb, ee, 32);
                                    memcpy(sb + 32, es, 32);
                                    memcpy(sb + 64, se, 32);
                                    memcpy(sb + 96, "shared", 6);
                                    sha256_h(sh, sb, 102);
                                }

                                /* Session keys */
                                {
                                    uint8_t sk[39]; memcpy(sk, sh, 32);
                                    memcpy(sk + 32, "session", 7);
                                    sha256_h(h, sk, 39);
                                }
                                memcpy(keys.dec_key, h, 16);
                                memcpy(keys.enc_key, h + 16, 16);

                                /* Send RESP */
                                {
                                    uint8_t rk[16], rkb[36];
                                    memcpy(rkb, sh, 32);
                                    memcpy(rkb + 32, "resp", 4);
                                    sha256_h(h, rkb, 36); memcpy(rk, h, 16);
                                    uint8_t rdgram[UDP_HS_DGRAM];
                                    udp_hs_build(rdgram, epk, timestamp_now(), rk);
                                    sendto(udp_fd, rdgram, sizeof(rdgram), 0,
                                           (struct sockaddr *)&sender, sizeof(sender));
                                }
                                log_info("udp-server", "RESP sent");

                                /* Send KEY_CONFIRM */
                                {
                                    uint8_t kw[FRAME_MAX_WIRE]; size_t kwl;
                                    frame_build(kw, &kwl, FRAME_KEYCONFIRM, 0,
                                                NULL, 0, 0, keys.enc_key);
                                    sendto(udp_fd, kw, kwl, 0,
                                           (struct sockaddr *)&sender, sizeof(sender));
                                }
                                log_info("udp-server", "KEY_CONFIRM sent, waiting...");

                                /* Receive client KEY_CONFIRM (with g_running poll) */
                                {
                                    uint8_t ckw[FRAME_HEADER_LEN + AEGIS_TAG_LEN];
                                    ssize_t cnr = -1;
                                    while (g_running) {
                                        struct pollfd pfd;
                                        pfd.fd = udp_fd; pfd.events = POLLIN;
                                        int pr = poll(&pfd, 1, 500);
                                        if (pr < 0) { if (errno == EINTR) continue; break; }
                                        if (pr == 0) continue;  /* timeout — check g_running */
                                        cnr = recvfrom(udp_fd, ckw, sizeof(ckw), 0,
                                                       (struct sockaddr *)&sender, &slen);
                                        break;
                                    }
                                    if (cnr >= (ssize_t)sizeof(ckw)) {
                                        uint8_t ty, fl, dum[1]; size_t dl;
                                        if (frame_parse(ckw, sizeof(ckw), &ty, &fl,
                                                        dum, &dl, 0, keys.dec_key) == 0 &&
                                            ty == FRAME_KEYCONFIRM) {
                                            ok = 1;
                                        }
                                    }
                                }

                                secure_memzero(ee, 32); secure_memzero(es_init, 32);
                                secure_memzero(ek, 32); secure_memzero(sh, 32);
                                break;  /* done with this peer */
                            }
                        }

                        if (ok && peer_matched >= 0) {
                            log_info("udp-server", "peer #%d authenticated", peer_matched);

                            /* Add/update session in table */
                            int si = session_find(sessions, session_count, &sender);
                            if (si < 0 && session_count < UDP_MAX_CLIENTS) {
                                si = session_count++;
                                sessions[si].tun_ip = g_peer_tun_ips[peer_matched];
                            }
                            if (si >= 0) {
                                sessions[si].addr = sender;  /* update port (NAT rebinding) */
                                memcpy(sessions[si].enc_key, keys.enc_key, 16);
                                memcpy(sessions[si].dec_key, keys.dec_key, 16);
                                sessions[si].last_seen = (int64_t)time(NULL);
                                sessions[si].active = 1;
                            }
                        } else {
                            log_warn("udp-server", "handshake failed (peer %d)",
                                     peer_matched);
                        }
                        secure_memzero(&keys, sizeof(keys));
                    }
                    continue;
                }

                /* ── Data frame from known client ── */
                {
                    int si = session_find(sessions, session_count, &sender);
                    if (si < 0) {
                        /* Unknown client — maybe a stale handshake retry */
                        if (buf[0] != FRAME_HANDSHAKE)
                            log_info("udp-server", "data from unknown %s:%d (type=%d, len=%zd)",
                                     inet_ntop(AF_INET, &sender.sin_addr,
                                               (char[INET_ADDRSTRLEN]){}, INET_ADDRSTRLEN),
                                     ntohs(sender.sin_port), buf[0], nr);
                        continue;
                    }

                    /* Update port — client may have reconnected from a new port */
                    if (sessions[si].addr.sin_port != sender.sin_port) {
                        log_info("udp-server", "client port changed %d→%d, updating",
                                 ntohs(sessions[si].addr.sin_port),
                                 ntohs(sender.sin_port));
                        sessions[si].addr.sin_port = sender.sin_port;
                    }

                    uint8_t ty, fl, pkt[FRAME_MAX_PAYLOAD]; size_t pl;
                    if (frame_parse_explicit(buf, (size_t)nr, &ty, &fl,
                                              pkt, &pl, sessions[si].dec_key) == 0) {
                        sessions[si].last_seen = (int64_t)time(NULL);
                        log_info("udp-server", "UDP→TUN: ty=%d, %zu bytes", ty, pl);
                        if (ty == FRAME_DATA && pl > 0) {
                            ssize_t ww = write(tun_fd, pkt, pl);
                            if (ww < 0)
                                log_warn("udp-server", "TUN write error: %s", strerror(errno));
                            else if ((size_t)ww < pl) {
                                size_t wr = (size_t)ww;
                                while (wr < pl) {
                                    ssize_t w = write(tun_fd, pkt + wr, pl - wr);
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
            }
        }

        /* ── TUN → UDP ── */
        if (fds[1].revents & POLLIN) {
            log_info("udp-server", "TUN readable (revents=0x%x)", fds[1].revents);
            for (;;) {
                if (!g_running) break;
                uint8_t pkt[FRAME_MAX_PAYLOAD];
                ssize_t n = read(tun_fd, pkt, sizeof(pkt));
                if (n < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                    log_warn("udp-server", "TUN read error: %s", strerror(errno));
                    goto srv_out;
                }
                if (n <= 0) {
                    log_info("udp-server", "TUN read EOF (n=%zd)", n);
                    goto srv_out;
                }

                log_info("udp-server", "TUN→UDP: read %zd bytes, ver=%d",
                         n, (pkt[0] >> 4));

                /* Route by destination IP in the IP header */
                uint32_t dst = ip_dst_addr(pkt, (size_t)n);
                int sent = 0;
                for (int si = 0; si < session_count; si++) {
                    if (!sessions[si].active) continue;
                    log_info("udp-server", "  session[%d] active, tun_ip=0x%x, dst=0x%x",
                             si, sessions[si].tun_ip, dst);
                    if (dst != 0 && sessions[si].tun_ip != 0 &&
                        dst != sessions[si].tun_ip) {
                        log_info("udp-server", "  → skip (dst mismatch)");
                        continue;
                    }

                    uint8_t wb[FRAME_EXPLICIT_MAX_WIRE]; size_t wl;
                    if (frame_build_explicit(wb, &wl, FRAME_DATA, 0,
                                              pkt, (size_t)n,
                                              sessions[si].enc_key) == 0) {
                        ssize_t sn = sendto(udp_fd, wb, wl, 0,
                               (struct sockaddr *)&sessions[si].addr,
                               sizeof(sessions[si].addr));
                        log_info("udp-server", "  → sendto → %s:%d returned %zd (errno=%d)",
                                 inet_ntop(AF_INET, &sessions[si].addr.sin_addr,
                                           (char[INET_ADDRSTRLEN]){}, INET_ADDRSTRLEN),
                                 ntohs(sessions[si].addr.sin_port), sn, errno);
                        sent++;
                    }
                }
                if (sent == 0)
                    log_info("udp-server", "TUN pkt dst=0x%x, no matching session (%d active)",
                             dst, session_count);
            }
        }

        /* ── Keepalive / stale session cleanup ── */
        {
            int64_t now = (int64_t)time(NULL);
            for (int si = 0; si < session_count; si++) {
                if (!sessions[si].active) continue;
                if (keepalive > 0 && now - sessions[si].last_seen >= keepalive) {
                    uint8_t kw[FRAME_EXPLICIT_MAX_WIRE]; size_t kwl;
                    if (frame_build_explicit(kw, &kwl, FRAME_KEEPALIVE, 0,
                                              NULL, 0, sessions[si].enc_key) == 0)
                        sendto(udp_fd, kw, kwl, 0,
                               (struct sockaddr *)&sessions[si].addr,
                               sizeof(sessions[si].addr));
                    sessions[si].last_seen = now;
                }
                /* Remove sessions idle for > 5 minutes */
                if (now - sessions[si].last_seen > 300) {
                    secure_memzero(&sessions[si], sizeof(sessions[si]));
                    sessions[si].active = 0;
                }
            }
        }
    }

srv_out:
    /* Clean up active sessions */
    for (int si = 0; si < session_count; si++)
        secure_memzero(&sessions[si], sizeof(sessions[si]));

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

    while (g_running) {
        int udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (udp_fd < 0) { sleep(1); continue; }

        /*
         * Set SO_MARK BEFORE any packets are sent (including DNS
         * during getaddrinfo, which uses its own sockets and cannot
         * be marked — but the connect() handshake datagrams must
         * bypass the TUN routing table).
         *
         * fwmark policy (set up by tun_set_fwmark_rule):
         *   unmarked packets → TUN table (VPN routes)
         *   marked  packets  → main table (physical NIC)
         */
        {
            int mark = 51820;
            setsockopt(udp_fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
        }

        struct addrinfo hints, *res;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET; hints.ai_socktype = SOCK_DGRAM;
        char ps[16]; snprintf(ps, sizeof(ps), "%d", remote_port);
        if (getaddrinfo(remote_host, ps, &hints, &res) != 0 || !res) {
            close(udp_fd); sleep(2); continue;
        }
        if (connect(udp_fd, res->ai_addr, res->ai_addrlen) < 0) {
            freeaddrinfo(res); close(udp_fd); sleep(2); continue;
        }
        freeaddrinfo(res);

        session_keys_t keys;
        if (udp_handshake_client(udp_fd, 0, &keys, hs_timeout) != 0) {
            log_warn("udp-client", "handshake failed");
            close(udp_fd); sleep(2); continue;
        }

        log_info("udp-client", "connected");

        /*
         * UDP data path uses explicit-nonce frames: each datagram
         * carries its own 8-byte nonce.  Packet loss or reordering
         * does not desynchronise the nonce counters.
         */
        int64_t last_ka = (int64_t)time(NULL);
        struct pollfd fds[2];
        fds[0].fd = tun_fd; fds[0].events = POLLIN;
        fds[1].fd = udp_fd; fds[1].events = POLLIN;

        while (g_running) {
            fds[0].revents = 0; fds[1].revents = 0;
            int pr = poll(fds, 2, keepalive > 0 ? keepalive * 1000 : 500);
            if (pr < 0) { if (errno == EINTR) continue; break; }

            /* TUN → UDP: one IP packet → one explicit-nonce frame */
            if (fds[0].revents & POLLIN) {
                for (;;) {
                    uint8_t pkt[FRAME_MAX_PAYLOAD];
                    ssize_t n = read(tun_fd, pkt, sizeof(pkt));
                    if (n < 0) { if (errno == EAGAIN || errno == EWOULDBLOCK) break; goto disconnect; }
                    if (n <= 0) goto disconnect;
                    uint8_t wb[FRAME_EXPLICIT_MAX_WIRE]; size_t wl;
                    if (frame_build_explicit(wb, &wl, FRAME_DATA, 0, pkt, (size_t)n, keys.enc_key) == 0)
                        send(udp_fd, wb, wl, 0);
                }
            }

            /* UDP → TUN: extract nonce from wire, decrypt, forward */
            if (fds[1].revents & POLLIN) {
                for (;;) {
                    uint8_t wb[UDP_MAX_DGRAM];
                    ssize_t n = recv(udp_fd, wb, sizeof(wb), 0);
                    if (n < 0) { if (errno == EAGAIN || errno == EWOULDBLOCK) break; goto disconnect; }
                    if (n == 0) goto disconnect;
                    uint8_t ty, fl, pkt[FRAME_MAX_PAYLOAD]; size_t pl;
                    if (frame_parse_explicit(wb, (size_t)n, &ty, &fl, pkt, &pl, keys.dec_key) == 0) {
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

            /* Keepalive — also uses explicit nonce */
            {
                int64_t now = (int64_t)time(NULL);
                if (keepalive > 0 && now - last_ka >= keepalive) {
                    uint8_t kw[FRAME_EXPLICIT_MAX_WIRE]; size_t kwl;
                    if (frame_build_explicit(kw, &kwl, FRAME_KEEPALIVE, 0, NULL, 0, keys.enc_key) == 0)
                        send(udp_fd, kw, kwl, 0);
                    last_ka = now;
                }
            }
        }
    disconnect:
        secure_memzero(&keys, sizeof(keys));
        close(udp_fd);
        log_info("udp-client", "disconnected, reconnecting...");
        sleep(2);
    }

    tun_run_postdown(postdown, name);
    tun_teardown(name, 0);
    close(tun_fd);
    return 0;
}
