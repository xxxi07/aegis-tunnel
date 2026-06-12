/*
 * tunnel.c — TCP tunnel core implementation
 *
 * Implements the frame protocol and the poll()-based event loop
 * that drives the encrypted tunnel.
 *
 * Each frame is independently encrypted with a unique nonce
 * (derived from a monotonic counter).
 */
#include "tunnel/tunnel.h"
#include "protocol/frame_reader.h"
#include "protocol/handshake.h"
#include "util/log.h"
#include "util/util.h"

#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* ─── Nonce construction ───────────────────────────────────────── */

#define NONCE_OVERFLOW_LIMIT  (UINT64_C(0xFFFFFFFFFFFFFFF0))

static void nonce_from_counter(uint8_t nonce[AEGIS_NONCE_LEN],
                               uint64_t counter)
{
    memset(nonce, 0, AEGIS_NONCE_LEN);
    for (int i = 0; i < 8; i++) {
        nonce[i] = (uint8_t)(counter & 0xff);
        counter >>= 8;
    }
}

/* ─── Frame: build encrypted wire frame ────────────────────────── */

int frame_build(uint8_t *buf, size_t *out_len,
                uint8_t type, uint8_t flags,
                const uint8_t *d, size_t len,
                uint64_t nonce_ctr,
                const uint8_t key[AEGIS_KEY_LEN])
{
    if (len > FRAME_MAX_PAYLOAD) return -1;

    uint8_t *header = buf;
    uint8_t *ct     = buf + FRAME_HEADER_LEN;
    uint8_t *tag    = buf + FRAME_HEADER_LEN + len;

    header[0] = type;
    header[1] = flags;
    header[2] = (uint8_t)((len >> 8) & 0xff);
    header[3] = (uint8_t)(len & 0xff);

    uint8_t nonce[AEGIS_NONCE_LEN];
    nonce_from_counter(nonce, nonce_ctr);

    aegis_encrypt(ct, tag, d, len, header, FRAME_HEADER_LEN, nonce, key);
    *out_len = FRAME_HEADER_LEN + len + AEGIS_TAG_LEN;
    return 0;
}

/* ─── Frame: parse and decrypt wire frame ──────────────────────── */

int frame_parse(const uint8_t *buf, size_t buflen,
                uint8_t *type, uint8_t *flags,
                uint8_t *d, size_t *dlen,
                uint64_t nonce_ctr,
                const uint8_t key[AEGIS_KEY_LEN])
{
    if (buflen < FRAME_HEADER_LEN + AEGIS_TAG_LEN) return -1;

    const uint8_t *header = buf;
    const uint8_t *ct     = buf + FRAME_HEADER_LEN;

    *type  = header[0];
    *flags = header[1];
    size_t payload_len = (size_t)(((uint16_t)header[2] << 8) | header[3]);

    if (buflen != FRAME_HEADER_LEN + payload_len + AEGIS_TAG_LEN) return -1;
    if (payload_len > FRAME_MAX_PAYLOAD) return -1;

    const uint8_t *tag = ct + payload_len;

    uint8_t nonce[AEGIS_NONCE_LEN];
    nonce_from_counter(nonce, nonce_ctr);

    int ret = aegis_decrypt(d, ct, payload_len,
                            header, FRAME_HEADER_LEN,
                            nonce, key, tag);
    if (ret != 0) return -1;

    *dlen = payload_len;
    return 0;
}

/* ─── Tunnel: initialize context ───────────────────────────────── */

void tunnel_init(tunnel_t *tun,
                 int plaintext_fd, int encrypted_fd,
                 const uint8_t enc_key[AEGIS_KEY_LEN],
                 const uint8_t dec_key[AEGIS_KEY_LEN])
{
    memset(tun, 0, sizeof(*tun));
    tun->fd[TUNNEL_PLAINTEXT_FD] = plaintext_fd;
    tun->fd[TUNNEL_ENCRYPTED_FD] = encrypted_fd;
    memcpy(tun->enc_key, enc_key, AEGIS_KEY_LEN);
    memcpy(tun->dec_key, dec_key, AEGIS_KEY_LEN);
    tun->enc_nonce = 1;   /* 0 reserved for handshake */
    tun->dec_nonce = 1;
    tun->keepalive_sec = 0;
    tun->running = 1;
}

/* ─── Tunnel: send a DATA frame (encrypt direction) ────────────── */

int tunnel_send_data(tunnel_t *tun,
                     const uint8_t *d, size_t len)
{
    /* Check nonce overflow */
    if (tun->enc_nonce >= NONCE_OVERFLOW_LIMIT) {
        return -1;
    }

    uint8_t wire_buf[FRAME_MAX_WIRE];
    size_t wire_len = 0;

    if (frame_build(wire_buf, &wire_len, FRAME_DATA, FLAG_NONE,
                    d, len, tun->enc_nonce, tun->enc_key) != 0) {
        return -1;
    }
    tun->enc_nonce++;

    /* Send with partial-write retry */
    size_t sent = 0;
    while (sent < wire_len) {
        ssize_t n = send(tun->fd[TUNNEL_ENCRYPTED_FD],
                         wire_buf + sent, wire_len - sent, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
            return -1;
        }
        sent += (size_t)n;
    }
    return (int)wire_len;
}

/* ─── Tunnel: forward decrypted payload to destination ─────────── */
/*
 * Send plaintext bytes to dst_fd with partial-write retry.
 * Returns 0 on success, -1 on error.
 */
static int send_all(int dst_fd, const uint8_t *data, size_t len)
{
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(dst_fd, data + sent, len - sent, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
            return -1;
        }
        sent += (size_t)n;
    }
    return 0;
}

/* ─── Tunnel: main event loop ──────────────────────────────────── */

int tunnel_run(tunnel_t *tun)
{
    struct pollfd fds[2];
    int pt_fd  = tun->fd[TUNNEL_PLAINTEXT_FD];
    int enc_fd = tun->fd[TUNNEL_ENCRYPTED_FD];
    frame_reader_t fr;
    frame_reader_init(&fr, enc_fd);

    int64_t last_ka    = (int64_t)time(NULL);
    int64_t last_rekey = (int64_t)time(NULL);

    while (tun->running) {
        fds[0].fd = pt_fd;
        fds[0].events = POLLIN;
        fds[0].revents = 0;
        fds[1].fd = enc_fd;
        fds[1].events = POLLIN;
        fds[1].revents = 0;

        int ret = poll(fds, 2, 500);
        if (ret < 0) {
            if (errno == EINTR) continue;
            log_warn("tunnel", "poll error: %s", strerror(errno));
            return -1;
        }

        /* ── Plaintext → Encrypted: read, encrypt, forward ── */
        if (fds[TUNNEL_PLAINTEXT_FD].revents & POLLIN) {
            uint8_t buf[FRAME_MAX_PAYLOAD];
            ssize_t n = recv(pt_fd, buf, sizeof(buf), 0);
            if (n < 0) {
                if (errno == EINTR) continue;
                if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
                log_warn("tunnel", "pt_fd recv error: %s (fd=%d)", strerror(errno), pt_fd);
                return -1;
            }
            if (n == 0) {
                /* Plaintext peer disconnected — send CLOSE */
                uint8_t wb[FRAME_MAX_WIRE];
                size_t wl = 0;
                if (tun->enc_nonce < NONCE_OVERFLOW_LIMIT &&
                    frame_build(wb, &wl, FRAME_CLOSE, FLAG_NONE,
                                NULL, 0, tun->enc_nonce, tun->enc_key) == 0) {
                    tun->enc_nonce++;
                    send(enc_fd, wb, wl, MSG_NOSIGNAL);
                }
                return 0;
            }

            if (tunnel_send_data(tun, buf, (size_t)n) < 0)
                return -1;
        }

        /* ── Encrypted → Plaintext: buffered stream frame reader ── */
        if (fds[TUNNEL_ENCRYPTED_FD].revents & POLLIN) {
            /*
             * 1. Drain available TCP data into the frame buffer.
             * 2. Extract ALL complete frames (handles TCP coalescing).
             * 3. Partial frames stay buffered for next poll() cycle.
             */
            int fill = frame_reader_fill(&fr);
            if (fill < 0) { log_warn("tunnel", "enc_fd read error (fd=%d)", enc_fd); return -1; }
            if (fill == 0) { log_info("tunnel", "enc_fd EOF (peer disconnected)"); return 0; }

            for (;;) {
                if (tun->dec_nonce >= NONCE_OVERFLOW_LIMIT)
                    return -1;

                uint8_t f_type, f_flags;
                uint8_t plaintext[FRAME_MAX_PAYLOAD];
                size_t plen = 0;

                int r = frame_reader_try_next(&fr, &f_type, &f_flags,
                                              plaintext, &plen,
                                              tun->dec_nonce, tun->dec_key);
                if (r == 0) break;    /* need more data — wait for next poll */
                if (r < 0) { log_warn("tunnel", "frame auth/parse failed (nonce=%lu)", (unsigned long)tun->dec_nonce); return -1; }

                tun->dec_nonce++;

                if (f_type == FRAME_CLOSE) return 0;
                if (f_type == FRAME_KEEPALIVE) continue;
                if (f_type == FRAME_KEYCONFIRM) continue;
                if (f_type == FRAME_REKEY) {
                    /* Peer wants to re-key.  handshake_rekey() handles
                     * the full ECDH exchange and replaces keys atomically. */
                    if (tun->psk && tun->psk_len > 0) {
                        extern int handshake_rekey(int, const uint8_t*, size_t,
                                                   session_keys_t*, uint64_t*, int);
                        session_keys_t sk;
                        memcpy(sk.enc_key, tun->enc_key, AEGIS_KEY_LEN);
                        memcpy(sk.dec_key, tun->dec_key, AEGIS_KEY_LEN);
                        uint64_t ctr = tun->dec_nonce;
                        if (handshake_rekey(tun->fd[TUNNEL_ENCRYPTED_FD],
                                            tun->psk, tun->psk_len,
                                            &sk, &ctr, 0) == 0) {
                            memcpy(tun->enc_key, sk.enc_key, AEGIS_KEY_LEN);
                            memcpy(tun->dec_key, sk.dec_key, AEGIS_KEY_LEN);
                            tun->dec_nonce = ctr;
                        }
                    }
                    continue;
                }
                if (plen > 0 && send_all(pt_fd, plaintext, plen) != 0)
                    return -1;
            }
        }

        /* ── Error conditions ── */
        if (fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) return 0;
        if (fds[1].revents & (POLLERR | POLLHUP | POLLNVAL)) return 0;

        /* ── Keepalive ── */
        if (tun->keepalive_sec > 0 && tun->enc_nonce < NONCE_OVERFLOW_LIMIT) {
            int64_t now = (int64_t)time(NULL);
            if (now - last_ka >= tun->keepalive_sec) {
                uint8_t wb[FRAME_MAX_WIRE];
                size_t wl = 0;
                if (frame_build(wb, &wl, FRAME_KEEPALIVE, FLAG_NONE,
                                NULL, 0, tun->enc_nonce, tun->enc_key) == 0) {
                    tun->enc_nonce++;
                    send(enc_fd, wb, wl, MSG_NOSIGNAL);
                }
                last_ka = now;
            }
        }

        /* ── Session Re-Keying (periodic ECDH, WireGuard-style) ── */
        if (tun->rekey_sec > 0 && tun->psk && tun->psk_len > 0
            && tun->enc_nonce < NONCE_OVERFLOW_LIMIT) {
            int64_t now = (int64_t)time(NULL);
            if (now - last_rekey >= tun->rekey_sec) {
                /* Initiate re-key: new ECDH exchange, new session keys.
                 * The peer handles FRAME_REKEY automatically in the
                 * encrypted→plaintext path above. */
                session_keys_t nk;
                memcpy(nk.enc_key, tun->enc_key, AEGIS_KEY_LEN);
                memcpy(nk.dec_key, tun->dec_key, AEGIS_KEY_LEN);
                uint64_t ctr = tun->enc_nonce;
                if (handshake_rekey(tun->fd[TUNNEL_ENCRYPTED_FD],
                                    tun->psk, tun->psk_len,
                                    &nk, &ctr, 1 /* initiator */) == 0) {
                    memcpy(tun->enc_key, nk.enc_key, AEGIS_KEY_LEN);
                    memcpy(tun->dec_key, nk.dec_key, AEGIS_KEY_LEN);
                    tun->enc_nonce = ctr;
                }
                secure_memzero(&nk, sizeof(nk));
                last_rekey = now;
            }
        }
    }
    return 0;
}
