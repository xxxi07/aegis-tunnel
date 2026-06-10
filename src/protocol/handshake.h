/*
 * handshake.h — Asymmetric handshake with 3-DH X25519 key exchange
 *
 * Each peer has its own X25519 static keypair:
 *   private key — kept secret on this machine (32 bytes)
 *   public key  — shared with peers out of band (32 bytes)
 *
 * Authentication via static keypairs, forward secrecy via ephemeral ECDH.
 * WireGuard model: no shared PSK needed.
 */
#ifndef HANDSHAKE_H
#define HANDSHAKE_H

#include "crypto/aegis.h"
#include <stddef.h>
#include <stdint.h>

#define HANDSHAKE_PSK_MIN_LEN  16   /* kept for API compat */

/* ─── Frame types ──────────────────────────────────────────────── */
#define FRAME_HANDSHAKE    0x01
#define FRAME_DATA         0x02
#define FRAME_KEEPALIVE    0x03
#define FRAME_CLOSE        0x04
#define FRAME_KEYCONFIRM   0x05
#define FRAME_REKEY        0x06

#define FLAG_NONE          0x00
#define HANDSHAKE_NONCE_LEN  16
#define HANDSHAKE_TS_LEN      8
#define HANDSHAKE_PUBKEY_LEN 32
#define HANDSHAKE_PAYLOAD_LEN (HANDSHAKE_NONCE_LEN + HANDSHAKE_TS_LEN + HANDSHAKE_PUBKEY_LEN)

/* ─── Session keys ─────────────────────────────────────────────── */
typedef struct {
    uint8_t enc_key[AEGIS_KEY_LEN];
    uint8_t dec_key[AEGIS_KEY_LEN];
} session_keys_t;

/* ─── Handshake API ────────────────────────────────────────────── */

/* Server: 3-DH asymmetric handshake */
int handshake_server(int fd,
                     const uint8_t our_priv[32],
                     const uint8_t peer_pub[32],
                     int timeout_ms,
                     session_keys_t *keys);

/* Client: 3-DH asymmetric handshake */
int handshake_client(int fd,
                     const uint8_t our_priv[32],
                     const uint8_t peer_pub[32],
                     int timeout_ms,
                     session_keys_t *keys);

/* Key confirmation */
int handshake_key_confirm_server(int fd, const session_keys_t *keys, int timeout_ms);
int handshake_key_confirm_client(int fd, const session_keys_t *keys, int timeout_ms);

/* Session re-keying */
int handshake_rekey(int fd,
                    const uint8_t *psk, size_t psk_len,
                    session_keys_t *keys, uint64_t *nonce_ctr,
                    int is_initiator);

#endif /* HANDSHAKE_H */
