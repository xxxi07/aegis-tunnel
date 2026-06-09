/*
 * keyfile.h — Asymmetric key management (WireGuard model)
 *
 * Each peer has:
 *   - A static X25519 keypair:  private key (kept secret on this machine)
 *                               public key  (shared with peers)
 *   - Peer public keys:         one per remote peer
 *
 * Key files are raw 32-byte binary (like WireGuard):
 *   private.key:  32 bytes X25519 private key  (chmod 400)
 *   public.key:   32 bytes X25519 public key   (chmod 644, shareable)
 *
 * Usage:
 *   // Generate new keypair
 *   keyfile_generate("private.key", "public.key");
 *
 *   // Load keys
 *   uint8_t priv[32], pub[32], peer_pub[32];
 *   keyfile_load_private(priv, "private.key");
 *   keyfile_load_public(pub, "public.key");
 *   keyfile_load_public(peer_pub, "peer.pub");   // peer's public key
 *
 *   // Use in handshake (replaces PSK)
 *   handshake_asymmetric_client(fd, priv, peer_pub, timeout, &keys);
 */
#ifndef KEYFILE_H
#define KEYFILE_H

#include <stddef.h>
#include <stdint.h>

#define KEYFILE_KEY_LEN    32   /* X25519 key length */

/*
 * Generate a new X25519 keypair and write to files.
 *   priv_path: path to write private key (created chmod 400)
 *   pub_path:  path to write public key
 * Returns 0 on success, -1 on error.
 */
int keyfile_generate(const char *priv_path, const char *pub_path);

/*
 * Load a raw 32-byte key from file.
 * Returns 0 on success, -1 on error.
 */
int keyfile_load(uint8_t key[KEYFILE_KEY_LEN], const char *path);

/*
 * Load private key with permission check (must be 400 or 600).
 */
int keyfile_load_private(uint8_t key[KEYFILE_KEY_LEN], const char *path);

/*
 * Load public key (no permission restriction).
 */
int keyfile_load_public(uint8_t key[KEYFILE_KEY_LEN], const char *path);

#endif /* KEYFILE_H */
