/*
 * aegis.h — AEGIS-128 Authenticated Encryption with Associated Data
 *
 * Pure C99 implementation of the AEGIS-128 algorithm as specified in
 * draft-irtf-cfrg-aegis-aead (IETF CFRG).
 *
 * AEGIS-128 is a CAESAR competition winner that uses 5 × 128-bit state
 * words and the AES round function as its core permutation.
 *
 * Constants:
 *   Key length:   16 bytes (128 bits)
 *   Nonce length: 16 bytes (128 bits)
 *   Tag length:   16 bytes (128 bits)
 *   Block size:   16 bytes (128 bits)
 */
#ifndef AEGIS_H
#define AEGIS_H

#include <stddef.h>
#include <stdint.h>

/* ─── Algorithm constants ─────────────────────────────────────── */

#define AEGIS_KEY_LEN     16  /* 128-bit key */
#define AEGIS_NONCE_LEN   16  /* 128-bit nonce */
#define AEGIS_TAG_LEN     16  /* 128-bit authentication tag */
#define AEGIS_BLOCK_LEN   16  /* 128-bit processing block */
#define AEGIS_STATE_WORDS  5  /* 5 × 128-bit state words */

/* ─── State type ───────────────────────────────────────────────── */

/*
 * AEGIS-128 internal state: 5 words of 16 bytes each (640 bits total).
 * Each word fits exactly in one ARM NEON register (128-bit).
 */
typedef struct {
    uint8_t S[AEGIS_STATE_WORDS][AEGIS_BLOCK_LEN];
} aegis_state_t;

/* ─── One-shot API (stateless, per-message) ───────────────────── */

/*
 * Auto-detect the best crypto backend at startup.
 * Call once before any encrypt/decrypt operations.
 * On x86_64: tries AES-NI, falls back to pure C.
 * On aarch64: tries ARM Crypto, then NEON, falls back to pure C.
 */
void aegis_crypto_init(void);

/*
 * Encrypt plaintext with associated data.
 * (dispatches to the best available implementation chosen by aegis_crypto_init)
 */
void aegis_encrypt(uint8_t *c, uint8_t tag[AEGIS_TAG_LEN],
                   const uint8_t *m, size_t mlen,
                   const uint8_t *ad, size_t adlen,
                   const uint8_t nonce[AEGIS_NONCE_LEN],
                   const uint8_t key[AEGIS_KEY_LEN]);

/*
 * Decrypt ciphertext with associated data and verify tag.
 * (dispatches to the best available implementation chosen by aegis_crypto_init)
 *
 * Returns 0 on success, -1 on authentication failure.
 * On failure, the output buffer m is zeroed.
 */
int  aegis_decrypt(uint8_t *m,
                   const uint8_t *c, size_t clen,
                   const uint8_t *ad, size_t adlen,
                   const uint8_t nonce[AEGIS_NONCE_LEN],
                   const uint8_t key[AEGIS_KEY_LEN],
                   const uint8_t tag[AEGIS_TAG_LEN]);

/* ─── Streaming API (stateful, for large data) ─────────────────── */

/*
 * Initialize AEGIS state with key and nonce.
 * Runs the 10-round initialization procedure.
 */
void aegis_init(aegis_state_t *st,
                const uint8_t key[AEGIS_KEY_LEN],
                const uint8_t nonce[AEGIS_NONCE_LEN]);

/*
 * Process associated data (AD).
 * May be called multiple times with chunks of AD.
 * All AD must be processed before any encryption/decryption.
 */
void aegis_ad_update(aegis_state_t *st,
                     const uint8_t *ad, size_t adlen);

/*
 * Encrypt plaintext block(s).
 * dst and src may alias (in-place encryption is safe).
 * len should typically be a multiple of AEGIS_BLOCK_LEN;
 * the final partial block is handled by aegis_enc_final().
 */
void aegis_enc_update(aegis_state_t *st,
                      uint8_t *dst, const uint8_t *src, size_t len);

/*
 * Finalize encryption: process the final (possibly partial) block
 * and generate the 16-byte authentication tag.
 *
 *   dst: output ciphertext for final block (same length as len)
 *   src: final plaintext bytes (may be NULL if len == 0)
 *   len: number of bytes in final block (0..15)
 *   tag: output 16-byte authentication tag
 */
void aegis_enc_final(aegis_state_t *st,
                     uint8_t *dst, const uint8_t *src, size_t len,
                     uint8_t tag[AEGIS_TAG_LEN]);

/*
 * Decrypt ciphertext block(s).
 * dst and src may alias (in-place decryption is safe).
 */
void aegis_dec_update(aegis_state_t *st,
                      uint8_t *dst, const uint8_t *src, size_t len);

/*
 * Finalize decryption: process the final (possibly partial) block
 * and verify the 16-byte authentication tag.
 *
 * Returns 0 on success, -1 on authentication failure.
 * On failure, the output buffer is zeroed.
 */
int  aegis_dec_final(aegis_state_t *st,
                     uint8_t *dst, const uint8_t *src, size_t len,
                     const uint8_t tag[AEGIS_TAG_LEN]);

#endif /* AEGIS_H */
