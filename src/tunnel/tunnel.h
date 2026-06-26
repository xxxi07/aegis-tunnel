/*
 * tunnel.h — TCP tunnel core interface
 *
 * Implements the AEGIS-Tunnel wire protocol on top of TCP:
 * a minimal frame-based protocol with AEGIS-128 authenticated
 * encryption for each frame.
 *
 * Wire frame format:
 *   +------+------+--------+--------//--------+--------//--------+
 *   | type | flags| length |    payload        |    tag          |
 *   |  1   |  1   |  2 BE  |  0..65535 bytes   |   16 bytes      |
 *   +------+------+--------+--------//--------+--------//--------+
 *
 * The 4-byte frame header (type + flags + length) is passed as
 * Associated Data (AD) to AEGIS.  The payload is encrypted.
 * The 16-byte tag authenticates both AD and ciphertext.
 *
 * Nonce construction:
 *   nonce[16] = little_endian_64(counter) || 0x00 * 8
 * Each direction (enc, dec) maintains its own 64-bit counter
 * starting at 1 for data frames (0 is reserved for handshake).
 */
#ifndef TUNNEL_H
#define TUNNEL_H

#include "crypto/aegis.h"
#include <stddef.h>
#include <stdint.h>

/* ─── Frame constants ──────────────────────────────────────────── */

#define FRAME_HEADER_LEN   4   /* type(1) + flags(1) + length(2) */
#define FRAME_MAX_PAYLOAD  65535
#define FRAME_MAX_WIRE     (FRAME_HEADER_LEN + FRAME_MAX_PAYLOAD + AEGIS_TAG_LEN)

/*
 * Explicit-nonce frame (used for unreliable transports like UDP):
 *   [type:1][flags:1][length:2 BE][nonce:8 LE][payload:N][tag:16]
 *
 * The 8-byte nonce is embedded in the wire format so the receiver can
 * decrypt even when datagrams are lost or reordered.  The 12-byte
 * header (type+flags+length+nonce) is passed as AD to AEGIS.
 */
#define FRAME_EXPLICIT_HEADER_LEN  12   /* type(1) + flags(1) + length(2) + nonce(8) */
#define FRAME_EXPLICIT_MAX_WIRE    (FRAME_EXPLICIT_HEADER_LEN + FRAME_MAX_PAYLOAD + AEGIS_TAG_LEN)

/* ─── Frame types (shared with handshake.h) ───────────────────── */

#ifndef FRAME_HANDSHAKE
#define FRAME_HANDSHAKE  0x01
#define FRAME_DATA       0x02
#define FRAME_KEEPALIVE  0x03
#define FRAME_CLOSE      0x04
#endif

#ifndef FLAG_NONE
#define FLAG_NONE        0x00
#endif

/* ─── Data direction ──────────────────────────────────────────── */
/*
 * The tunnel has two sockets; their roles depend on perspective.
 *
 * TUNNEL_PLAINTEXT_FD:  unencrypted side  — local user (client)
 *                        or target service (server)
 * TUNNEL_ENCRYPTED_FD:  encrypted side   — peer tunnel endpoint
 *
 * Data flow in tunnel_run():
 *   plaintext_fd → encrypt(enc_key) → encrypted_fd
 *   encrypted_fd → decrypt(dec_key) → plaintext_fd
 */
typedef enum {
    TUNNEL_PLAINTEXT_FD  = 0,  /* fds[0] — plaintext source/dest */
    TUNNEL_ENCRYPTED_FD  = 1,  /* fds[1] — encrypted frame source/dest */
} tunnel_dir_t;

/* ─── Tunnel context ───────────────────────────────────────────── */

typedef struct {
    int  fd[2];                        /* fd[PLAINTEXT] and fd[ENCRYPTED] */
    uint8_t enc_key[AEGIS_KEY_LEN];   /* Key for plaintext→encrypted */
    uint8_t dec_key[AEGIS_KEY_LEN];   /* Key for encrypted→plaintext */
    uint64_t enc_nonce;               /* Nonce counter: plaintext→encrypted */
    uint64_t dec_nonce;               /* Nonce counter: encrypted→plaintext */
    int  keepalive_sec;               /* Keepalive interval (0 = disabled) */
    int  rekey_sec;                   /* Re-key interval (0=off, 120=WireGuard-like) */
    uint8_t session_psk[16];          /* auto-derived PSK for nonce-triggered re-key */
    const uint8_t *psk;               /* External PSK for re-keying (may be NULL; session_psk used as fallback) */
    size_t psk_len;                   /* PSK length in bytes */
    volatile int running;             /* Set to 0 to stop the tunnel loop */
} tunnel_t;

/* ─── Tunnel API ───────────────────────────────────────────────── */

/*
 * Initialize a tunnel context.
 *
 *   plaintext_fd:   unencrypted side (local user on client, target on server)
 *   encrypted_fd:   encrypted side (peer tunnel endpoint)
 *   enc_key:        16-byte key for plaintext → encrypted direction
 *   dec_key:        16-byte key for encrypted → plaintext direction
 */
void tunnel_init(tunnel_t *tun,
                 int plaintext_fd, int encrypted_fd,
                 const uint8_t enc_key[AEGIS_KEY_LEN],
                 const uint8_t dec_key[AEGIS_KEY_LEN]);

/*
 * Main tunnel event loop.
 *
 * Uses poll() to multiplex between plaintext_fd and encrypted_fd.
 * On each readable event:
 *   1. Read data from the source fd
 *   2. Encrypt or decrypt as appropriate
 *   3. Forward to the destination fd
 *
 * Returns:
 *   0  — clean shutdown (CLOSE frame or EOF)
 *   -1 — fatal error
 *
 * The loop continues until:
 *   - A CLOSE frame is received
 *   - Either socket is closed by the peer (EOF)
 *   - tun->running is set to 0 (e.g., by SIGINT handler)
 */
int  tunnel_run(tunnel_t *tun);

/*
 * Send a single DATA frame.
 * Handles encryption and framing internally.
 *
 * Returns total bytes written (including overhead) on success,
 * -1 on error.
 */
int  tunnel_send_data(tunnel_t *tun,
                      const uint8_t *d, size_t len);

/*
 * Build a complete encrypted wire frame.
 *
 *   buf:      output buffer (must be at least FRAME_MAX_WIRE bytes)
 *   out_len:  [out] total wire frame length
 *   type:     frame type (FRAME_DATA, FRAME_KEEPALIVE, FRAME_CLOSE)
 *   flags:    frame flags
 *   d:        payload data (may be NULL if len == 0)
 *   len:      payload length (0..FRAME_MAX_PAYLOAD)
 *   nonce_ctr: 64-bit nonce counter value
 *   key:      encryption key (16 bytes)
 *
 * Returns 0 on success, -1 on error.
 */
int  frame_build(uint8_t *buf, size_t *out_len,
                 uint8_t type, uint8_t flags,
                 const uint8_t *d, size_t len,
                 uint64_t nonce_ctr,
                 const uint8_t key[AEGIS_KEY_LEN]);

/*
 * Parse and decrypt a wire frame.
 *
 *   buf:      received wire frame
 *   buflen:   total bytes received
 *   type:     [out] frame type
 *   flags:    [out] frame flags
 *   d:        [out] decrypted payload buffer (at least FRAME_MAX_PAYLOAD)
 *   dlen:     [out] decrypted payload length
 *   nonce_ctr: 64-bit nonce counter value for this direction
 *   key:      decryption key (16 bytes)
 *
 * Returns 0 on success, -1 on authentication failure or
 * malformed frame.
 */
int  frame_parse(const uint8_t *buf, size_t buflen,
                 uint8_t *type, uint8_t *flags,
                 uint8_t *d, size_t *dlen,
                 uint64_t nonce_ctr,
                 const uint8_t key[AEGIS_KEY_LEN]);

/*
 * Build an encrypted frame with an explicit 8-byte nonce embedded
 * in the wire format.  The nonce is randomly generated and placed
 * after the length field.  The receiver extracts it from the wire,
 * so packet loss/reordering does not desynchronise nonce counters.
 *
 * Wire format:
 *   [type:1][flags:1][length:2 BE][nonce:8 LE][payload:N][tag:16]
 *
 * Returns 0 on success, -1 on error.
 * out_len is set to the total wire bytes written.
 */
int  frame_build_explicit(uint8_t *buf, size_t *out_len,
                           uint8_t type, uint8_t flags,
                           const uint8_t *d, size_t len,
                           const uint8_t key[AEGIS_KEY_LEN]);

/*
 * Parse and decrypt a frame with an explicit nonce.
 * The nonce is extracted from bytes [4..11] and used directly
 * for AEGIS decryption — no counter state is needed.
 *
 * Returns 0 on success, -1 on authentication failure or
 * malformed frame.
 */
int  frame_parse_explicit(const uint8_t *buf, size_t buflen,
                           uint8_t *type, uint8_t *flags,
                           uint8_t *d, size_t *dlen,
                           const uint8_t key[AEGIS_KEY_LEN]);

#endif /* TUNNEL_H */
