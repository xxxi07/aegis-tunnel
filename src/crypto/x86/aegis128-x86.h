/*
 * aegis128-x86.h — AES-NI accelerated AEGIS-128 (x86_64)
 *
 * Uses Intel AES-NI instructions (_mm_aesenc_si128) to accelerate
 * the AEGIS-128 state update.  AES-NI provides hardware SubBytes +
 * ShiftRows + MixColumns in a single instruction, making each of
 * the 5 AES rounds in State_Update128 execute in 1 CPU cycle.
 *
 * Performance expectation: 10-20x faster than pure C on x86_64
 * with AES-NI (all modern Intel/AMD CPUs since ~2010).
 *
 * This file is compiled only on x86_64 with -maes.
 */
#ifndef AEGIS128_X86_H
#define AEGIS128_X86_H

#ifdef __x86_64__

#include "crypto/aegis.h"
#include <emmintrin.h>    /* SSE2 */
#include <wmmintrin.h>    /* AES-NI */

/* ─── AES-NI state: 5 × __m128i vectors ───────────────────────── */

typedef struct {
    __m128i S[AEGIS_STATE_WORDS];   /* 5 × 128-bit SSE registers */
} aegis128_x86_state_t;

/* ─── Runtime detection ─────────────────────────────────────────── */

/* Returns 1 if AES-NI is available, 0 otherwise. */
int aegis128_x86_available(void);

/* ─── Streaming API (same interface as aegis.h) ─────────────────── */

void aegis128_x86_init(aegis128_x86_state_t *st,
                       const uint8_t key[AEGIS_KEY_LEN],
                       const uint8_t nonce[AEGIS_NONCE_LEN]);

void aegis128_x86_ad_update(aegis128_x86_state_t *st,
                            const uint8_t *ad, size_t adlen);

void aegis128_x86_enc_update(aegis128_x86_state_t *st,
                              uint8_t *dst, const uint8_t *src, size_t len);

void aegis128_x86_enc_final(aegis128_x86_state_t *st,
                             uint8_t *dst, const uint8_t *src, size_t len,
                             uint8_t tag[AEGIS_TAG_LEN]);

void aegis128_x86_dec_update(aegis128_x86_state_t *st,
                              uint8_t *dst, const uint8_t *src, size_t len);

int  aegis128_x86_dec_final(aegis128_x86_state_t *st,
                             uint8_t *dst, const uint8_t *src, size_t len,
                             const uint8_t tag[AEGIS_TAG_LEN]);

/* ─── One-shot API ──────────────────────────────────────────────── */

void aegis128_x86_encrypt(uint8_t *c, uint8_t tag[AEGIS_TAG_LEN],
                          const uint8_t *m, size_t mlen,
                          const uint8_t *ad, size_t adlen,
                          const uint8_t nonce[AEGIS_NONCE_LEN],
                          const uint8_t key[AEGIS_KEY_LEN]);

int  aegis128_x86_decrypt(uint8_t *m,
                          const uint8_t *c, size_t clen,
                          const uint8_t *ad, size_t adlen,
                          const uint8_t nonce[AEGIS_NONCE_LEN],
                          const uint8_t key[AEGIS_KEY_LEN],
                          const uint8_t tag[AEGIS_TAG_LEN]);

#endif /* __x86_64__ */
#endif /* AEGIS128_X86_H */
