/*
 * aegis128-armcrypto.h — ARMv8 Crypto Extension accelerated AEGIS-128
 *
 * Uses ARMv8 AES instructions (aese/aesmc) for hardware-accelerated
 * AES rounds.  Available on ARM Cortex-A72/A76, Apple M1/M2, etc.
 *
 * AES_ROUND(S) = vaesmcq_u8(vaeseq_u8(S, zero))
 *
 * This is the fastest ARM path (~5x over pure C, ~2x over Plain NEON).
 * Falls back to plain NEON (tbl/tbx) or pure C if AES instructions
 * are not available.
 *
 * Only compiles on aarch64 with -march=armv8-a+crypto.
 */
#ifndef AEGIS128_ARMCRYPTO_H
#define AEGIS128_ARMCRYPTO_H

#ifdef __aarch64__

#include "crypto/aegis.h"
#include <arm_neon.h>

/* ─── State ────────────────────────────────────────────────────── */

typedef struct {
    uint8x16_t S[AEGIS_STATE_WORDS];
} aegis128_armcrypto_state_t;

/* ─── Runtime detection ────────────────────────────────────────── */

/* Returns 1 if ARMv8 AES instructions are available */
int aegis128_armcrypto_available(void);

/* ─── Streaming API ────────────────────────────────────────────── */

void aegis128_armcrypto_init(aegis128_armcrypto_state_t *st,
                             const uint8_t key[AEGIS_KEY_LEN],
                             const uint8_t nonce[AEGIS_NONCE_LEN]);

void aegis128_armcrypto_ad_update(aegis128_armcrypto_state_t *st,
                                  const uint8_t *ad, size_t adlen);

void aegis128_armcrypto_enc_update(aegis128_armcrypto_state_t *st,
                                    uint8_t *dst, const uint8_t *src, size_t len);

void aegis128_armcrypto_enc_final(aegis128_armcrypto_state_t *st,
                                   uint8_t *dst, const uint8_t *src, size_t len,
                                   uint8_t tag[AEGIS_TAG_LEN]);

void aegis128_armcrypto_dec_update(aegis128_armcrypto_state_t *st,
                                    uint8_t *dst, const uint8_t *src, size_t len);

int  aegis128_armcrypto_dec_final(aegis128_armcrypto_state_t *st,
                                   uint8_t *dst, const uint8_t *src, size_t len,
                                   const uint8_t tag[AEGIS_TAG_LEN]);

/* ─── One-shot API ─────────────────────────────────────────────── */

void aegis128_armcrypto_encrypt(uint8_t *c, uint8_t tag[AEGIS_TAG_LEN],
                                const uint8_t *m, size_t mlen,
                                const uint8_t *ad, size_t adlen,
                                const uint8_t nonce[AEGIS_NONCE_LEN],
                                const uint8_t key[AEGIS_KEY_LEN]);

int  aegis128_armcrypto_decrypt(uint8_t *m,
                                const uint8_t *c, size_t clen,
                                const uint8_t *ad, size_t adlen,
                                const uint8_t nonce[AEGIS_NONCE_LEN],
                                const uint8_t key[AEGIS_KEY_LEN],
                                const uint8_t tag[AEGIS_TAG_LEN]);

#endif /* __aarch64__ */
#endif /* AEGIS128_ARMCRYPTO_H */
