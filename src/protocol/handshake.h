/*
 * handshake.h — PSK-authenticated + ECDH handshake with forward secrecy
 *
 * Hybrid key exchange:
 *   PSK   → mutual authentication (both sides must know it)
 *   X25519 → forward secrecy (ephemeral per-session keypairs)
 *
 * Even if the PSK is later compromised, past session keys are safe
 * because ephemeral X25519 private keys are destroyed after handshake.
 *
 * Handshake payload (encrypted with init_key from PSK):
 *   nonce[16] || timestamp[8] || ecdh_pubkey[32] = 56 bytes
 *
 * Session key:
 *   shared = X25519(our_privkey, peer_pubkey)
 *   session_secret = SHA256(PSK || shared || client_nonce || server_nonce)
 */
#ifndef HANDSHAKE_H
#define HANDSHAKE_H

#include "crypto/aegis.h"
#include <stddef.h>
#include <stdint.h>

/* ─── Frame types ──────────────────────────────────────────────── */

#define FRAME_HANDSHAKE    0x01
#define FRAME_DATA         0x02
#define FRAME_KEEPALIVE    0x03
#define FRAME_CLOSE        0x04
#define FRAME_KEYCONFIRM   0x05   /* post-handshake key confirmation */
#define FRAME_REKEY        0x06   /* session re-keying (new ECDH pubkey) */
#define FRAME_TOFU         0x07   /* TOFU static public key exchange */
#define FLAG_NONE        0x00

/* ─── Handshake constants ──────────────────────────────────────── */

#define HANDSHAKE_NONCE_LEN    16
#define HANDSHAKE_TS_LEN        8
#define HANDSHAKE_PUBKEY_LEN   32   /* X25519 public key */
#define HANDSHAKE_PAYLOAD_LEN  (HANDSHAKE_NONCE_LEN + HANDSHAKE_TS_LEN + HANDSHAKE_PUBKEY_LEN)  /* 56 */
#define HANDSHAKE_PSK_MIN_LEN  16

/* ─── Session keys ─────────────────────────────────────────────── */

typedef struct {
    uint8_t enc_key[AEGIS_KEY_LEN];
    uint8_t dec_key[AEGIS_KEY_LEN];
} session_keys_t;

/* ─── API ──────────────────────────────────────────────────────── */

int handshake_server(int fd,
                     const uint8_t *psk, size_t psk_len,
                     int timeout_ms,
                     session_keys_t *keys);

int handshake_client(int fd,
                     const uint8_t *psk, size_t psk_len,
                     int timeout_ms,
                     session_keys_t *keys);

/*
 * Perform key confirmation after handshake.
 *
 * After the handshake completes, the server sends an encrypted
 * empty frame (FRAME_KEYCONFIRM) using the new session key.
 * The client decrypts it — success proves both sides have
 * matching session keys.  This is WireGuard's Transport Data
 * pattern applied to AEGIS-Tunnel.
 *
 * Call handshake_key_confirm_server() immediately after
 * handshake_server() succeeds.
 * Call handshake_key_confirm_client() immediately after
 * handshake_client() succeeds.
 *
 * Returns 0 on success, -1 if keys don't match.
 */
int handshake_key_confirm_server(int fd,
                                 const session_keys_t *keys,
                                 int timeout_ms);

int handshake_key_confirm_client(int fd,
                                 const session_keys_t *keys,
                                 int timeout_ms);

/*
 * Re-key a running tunnel session.
 *
 * Performs a fresh ECDH key exchange within the encrypted tunnel,
 * producing new session keys.  Call when:
 *   - Timer elapsed (e.g., every 2 minutes, like WireGuard)
 *   - Byte count exceeded (e.g., every 1 GB)
 *
 * Parameters:
 *   fd:       the tunnel socket (encrypted side)
 *   psk:      pre-shared key
 *   psk_len:  PSK length
 *   keys:     [in/out] current keys → replaced with new keys
 *   nonce_ctr:[in/out] nonce counter — reset after re-key
 *   is_initiator: 1 if we initiate re-key, 0 if we respond
 *
 * Returns 0 on success, -1 on failure.
 */
int handshake_rekey(int fd,
                    const uint8_t *psk, size_t psk_len,
                    session_keys_t *keys, uint64_t *nonce_ctr,
                    int is_initiator);

/*
 * Asymmetric handshake (WireGuard model, no shared secret).
 *
 * Each peer has its own X25519 static keypair:
 *   our_priv:  our static private key (32 bytes, keep secret)
 *   peer_pub:  peer's static public key (32 bytes, shared out-of-band)
 *
 * Authentication: 3-DH key exchange (es + ee + se)
 *   es = DH(our_static_priv, peer_static_pub)   → mutual authentication
 *   ee = DH(our_ephemeral,  peer_static_pub)   → encryption
 *   se = DH(our_static_priv, peer_ephemeral)    → responder auth
 *
 * Forward secrecy: ephemeral keys destroyed after handshake.
 * KCI resistance:   knowing static private key does not allow
 *                    impersonating OTHER peers to the key owner.
 *
 * PSK handshake (above) and asymmetric handshake (below) share
 * the same session_keys_t and key confirmation API.
 */
int handshake_asymmetric_server(int fd,
                                const uint8_t our_priv[32],
                                const uint8_t peer_pub[32],
                                int timeout_ms,
                                session_keys_t *keys);

int handshake_asymmetric_client(int fd,
                                const uint8_t our_priv[32],
                                const uint8_t peer_pub[32],
                                int timeout_ms,
                                session_keys_t *keys);

#endif /* HANDSHAKE_H */
