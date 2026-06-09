/*
 * tofu.h — Trust On First Use (TOFU) key management
 *
 * Like SSH known_hosts: peers' public keys are automatically
 * exchanged during the first connection and verified on subsequent
 * connections.  No pre-configuration needed.
 *
 * Storage (~/.aegis-tunnel/):
 *   private.key    — local static keypair (auto-generated on first use)
 *   public.key      — local public key
 *   known_hosts     — peer public keys (TOFU)
 *     Format: <host>:<port> <hex-pubkey>
 *
 * Workflow:
 *   First connection:
 *     tofu_ensure_keypair() → generates key if missing
 *     handshake exchanges public keys
 *     tofu_save_peer(host, port, peer_pubkey) → saves to known_hosts
 *
 *   Subsequent connections:
 *     tofu_load_peer(host, port, peer_pubkey) → loads saved key
 *     if loaded key ≠ received key → WARNING (possible MITM!)
 *     else → use asymmetric handshake with known keys
 */
#ifndef TOFU_H
#define TOFU_H

#include <stddef.h>
#include <stdint.h>

#define TOFU_KEY_LEN   32

/*
 * Ensure a keypair exists.  If ~/.aegis-tunnel/private.key doesn't
 * exist, generate a new X25519 keypair and store both keys.
 *   priv_out: [out] 32-byte private key
 *   pub_out:  [out] 32-byte public key
 * Returns 0 on success, -1 on error.
 */
int tofu_ensure_keypair(uint8_t priv_out[TOFU_KEY_LEN],
                        uint8_t pub_out[TOFU_KEY_LEN]);

/*
 * Store a peer's public key in known_hosts.
 *   host:     peer's hostname or IP
 *   port:     peer's port
 *   pubkey:   32-byte X25519 public key
 * Returns 0 on success, -1 on error.
 */
int tofu_save_peer(const char *host, int port,
                   const uint8_t pubkey[TOFU_KEY_LEN]);

/*
 * Load a previously-saved peer public key from known_hosts.
 *   host:     peer's hostname or IP
 *   port:     peer's port
 *   pubkey:   [out] 32-byte public key (filled if found)
 * Returns 1 if found, 0 if not found (first connection), -1 on error.
 */
int tofu_load_peer(const char *host, int port,
                   uint8_t pubkey[TOFU_KEY_LEN]);

/* Get the storage directory (~/.aegis-tunnel/) */
const char *tofu_dir(void);

/*
 * Exchange static public keys after a PSK handshake (TOFU bootstrap).
 *
 * After a PSK-authenticated handshake completes, both sides exchange
 * their long-term static public keys via encrypted frames, then save
 * the peer's key to known_hosts.
 *
 * Subsequent connections can then use the asymmetric handshake with
 * the stored keys, eliminating the PSK requirement.
 *
 * Parameters:
 *   fd:    tunnel socket (encrypted side)
 *   host:  peer hostname (for known_hosts)
 *   port:  peer port
 *   our_pubkey: our static public key to send
 *   enc_key:    session encryption key
 *   dec_key:    session decryption key
 *   is_server:  1 if we're the server (we receive first, then send)
 *
 * Returns 0 on success, -1 on error.
 * On success, peer's public key is saved to known_hosts.
 */
int tofu_exchange_keys(int fd,
                       const char *host, int port,
                       const uint8_t our_pubkey[TOFU_KEY_LEN],
                       const uint8_t enc_key[16],
                       const uint8_t dec_key[16],
                       int is_server);

#endif /* TOFU_H */
