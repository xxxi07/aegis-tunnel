/*
 * aegis128-plain.h — NEON-optimized AEGIS-128 interface
 *
 * This header is only valid when compiling for ARM aarch64 with
 * NEON SIMD support.  It provides a drop-in replacement for the
 * pure C streaming API, using NEON intrinsics (tbl/tbx) to
 * implement the AES round function without hardware AES support.
 *
 * On non-ARM platforms, this file is not compiled.
 */
#ifndef AEGIS128_PLAIN_H
#define AEGIS128_PLAIN_H

#ifdef __aarch64__

#include <arm_neon.h>
#include "crypto/aegis.h"

/*
 * AEGIS-128 state using NEON vector registers.
 * Each of the 5 state words is a 128-bit NEON register (uint8x16_t).
 */
typedef struct {
    uint8x16_t S[AEGIS_STATE_WORDS];
} aegis128_neon_state_t;

/* ─── NEON Streaming API ───────────────────────────────────────── */

void aegis128_neon_init(aegis128_neon_state_t *st,
                        const uint8_t key[AEGIS_KEY_LEN],
                        const uint8_t nonce[AEGIS_NONCE_LEN]);

void aegis128_neon_ad_update(aegis128_neon_state_t *st,
                             const uint8_t *ad, size_t adlen);

void aegis128_neon_enc_update(aegis128_neon_state_t *st,
                               uint8_t *dst, const uint8_t *src, size_t len);

void aegis128_neon_enc_final(aegis128_neon_state_t *st,
                              uint8_t *dst, const uint8_t *src, size_t len,
                              uint8_t tag[AEGIS_TAG_LEN]);

void aegis128_neon_dec_update(aegis128_neon_state_t *st,
                               uint8_t *dst, const uint8_t *src, size_t len);

int  aegis128_neon_dec_final(aegis128_neon_state_t *st,
                              uint8_t *dst, const uint8_t *src, size_t len,
                              const uint8_t tag[AEGIS_TAG_LEN]);

#endif /* __aarch64__ */
#endif /* AEGIS128_PLAIN_H */
