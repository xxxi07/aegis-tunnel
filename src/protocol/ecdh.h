/*
 * ecdh.h — X25519 Elliptic-Curve Diffie-Hellman key exchange
 *
 * Replaces static PSK with ephemeral key exchange for production
 * deployments.  Uses OpenSSL's X25519 implementation.
 *
 * Flow:
 *   Client:  ecdh_keygen()  → send pubkey to server
 *   Server:  ecdh_keygen()  → ecdh_derive(pubkey_c) → session_key
 *            send pubkey_s to client
 *   Client:  ecdh_derive(pubkey_s) → session_key
 *
 * Both sides now share the same session_key without ever
 * transmitting it over the wire.
 *
 * IMPORTANT: This provides secrecy but NOT authentication.
 * Combine with a long-term PSK or certificate for mutual auth.
 */
#ifndef ECDH_H
#define ECDH_H

#include <stddef.h>
#include <stdint.h>

#define ECDH_PUBKEY_LEN   32   /* X25519 public key */
#define ECDH_PRIVKEY_LEN  32   /* X25519 private key */
#define ECDH_SHARED_LEN   32   /* shared secret (SHA256 output) */

/*
 * Generate an ephemeral X25519 keypair.
 *   pubkey:  [out] 32-byte public key (send to peer)
 *   privkey: [out] 32-byte private key (keep secret, do not share)
 * Returns 0 on success, -1 on error.
 */
int ecdh_keygen(uint8_t pubkey[ECDH_PUBKEY_LEN],
                uint8_t privkey[ECDH_PRIVKEY_LEN]);

/*
 * Derive shared session key from our private key and peer's public key.
 *   shared_secret: [out] 32-byte SHA256(shared_point_x)
 *   our_privkey:   32-byte our private key
 *   peer_pubkey:   32-byte peer's public key
 * Returns 0 on success, -1 on error.
 */
int ecdh_derive(uint8_t shared_secret[ECDH_SHARED_LEN],
                const uint8_t our_privkey[ECDH_PRIVKEY_LEN],
                const uint8_t peer_pubkey[ECDH_PUBKEY_LEN]);

#endif /* ECDH_H */
