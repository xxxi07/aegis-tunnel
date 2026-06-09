/*
 * aegis128-x86.c — AES-NI accelerated AEGIS-128 implementation
 *
 * Uses Intel AES-NI: _mm_aesenc_si128(state, zero_key) performs
 * SubBytes + ShiftRows + MixColumns with a zero round key, which
 * is exactly the AES_ROUND() that AEGIS-128 requires.
 *
 * Key insight:
 *   AES_ROUND(S) ≡ _mm_aesenc_si128(S, _mm_setzero_si128())
 *
 * Each AEGIS State_Update128 (5 AES rounds + 5 XORs) becomes:
 *   ~15 SSE instructions, fully pipelined, no memory access.
 *
 * Performance: ~10-20x over pure C on AES-NI capable CPUs.
 */

#ifdef __x86_64__

#include "crypto/x86/aegis128-x86.h"
#include "util/util.h"

#include <cpuid.h>
#include <string.h>

/* ─── Runtime AES-NI detection via CPUID ────────────────────────── */

int aegis128_x86_available(void)
{
    unsigned int eax, ebx, ecx, edx;
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        return (ecx & bit_AES) ? 1 : 0;  /* CPUID.01H:ECX.AES[bit 25] */
    }
    return 0;
}

/* ─── Load/store helpers ────────────────────────────────────────── */

static inline __m128i load128(const uint8_t *p)
{
    return _mm_loadu_si128((const __m128i *)p);
}

static inline void store128(uint8_t *p, __m128i v)
{
    _mm_storeu_si128((__m128i *)p, v);
}

static inline __m128i load128u(const uint8_t p[16])
{
    __m128i v;
    memcpy(&v, p, 16);
    return v;
}

static inline void store128u(uint8_t p[16], __m128i v)
{
    memcpy(p, &v, 16);
}

/* ─── Core: AES round with zero key ─────────────────────────────── */
/*
 * aesenc(state, zero) = SubBytes + ShiftRows + MixColumns
 * This is the AES round function without AddRoundKey.
 */
static inline __m128i aes_round(__m128i s)
{
    return _mm_aesenc_si128(s, _mm_setzero_si128());
}

/* ─── XOR two vectors ───────────────────────────────────────────── */

static inline __m128i xor128(__m128i a, __m128i b) { return _mm_xor_si128(a, b); }
static inline __m128i and128(__m128i a, __m128i b) { return _mm_and_si128(a, b); }

/* ─── Key stream extraction ─────────────────────────────────────── */
/*
 * ks = S[1] ^ S[4] ^ (S[2] & S[3])
 */
static inline __m128i key_stream(__m128i S[5])
{
    return xor128(xor128(S[1], S[4]), and128(S[2], S[3]));
}

/* ─── State_Update128 (AES-NI) ──────────────────────────────────── */
/*
 * The heart of AEGIS-128, vectorized:
 *
 *   new_S[0] = AES_ROUND(S[4]) ^ S[0] ^ m
 *   new_S[1] = AES_ROUND(S[0]) ^ S[1]
 *   new_S[2] = AES_ROUND(S[1]) ^ S[2]
 *   new_S[3] = AES_ROUND(S[2]) ^ S[3]
 *   new_S[4] = AES_ROUND(S[3]) ^ S[4]
 *
 * Uses temp array to avoid overwriting values that later rounds need.
 */
static void state_update128(__m128i S[5], __m128i m)
{
    __m128i new_S[5];

    /* Compute all AES rounds first (fully parallelizable) */
    __m128i r0 = aes_round(S[4]);
    __m128i r1 = aes_round(S[0]);
    __m128i r2 = aes_round(S[1]);
    __m128i r3 = aes_round(S[2]);
    __m128i r4 = aes_round(S[3]);

    /* XOR chain */
    new_S[0] = xor128(xor128(r0, S[0]), m);
    new_S[1] = xor128(r1, S[1]);
    new_S[2] = xor128(r2, S[2]);
    new_S[3] = xor128(r3, S[3]);
    new_S[4] = xor128(r4, S[4]);

    S[0] = new_S[0]; S[1] = new_S[1]; S[2] = new_S[2];
    S[3] = new_S[3]; S[4] = new_S[4];
}

/* ─── AEGIS constants ───────────────────────────────────────────── */

static const uint8_t C0_bytes[16] = {
    0x00,0x01,0x01,0x02,0x03,0x05,0x08,0x0d,
    0x15,0x22,0x33,0x59,0x90,0xe9,0x62,0x62
};
static const uint8_t C1_bytes[16] = {
    0xdb,0x3d,0x18,0x55,0x6d,0xc2,0x2f,0xf1,
    0x20,0x11,0x31,0x42,0x73,0xb5,0x28,0xdd
};

/* ════════════════════════════════════════════════════════════════
 * Streaming API
 * ════════════════════════════════════════════════════════════════ */

void aegis128_x86_init(aegis128_x86_state_t *st,
                       const uint8_t key[AEGIS_KEY_LEN],
                       const uint8_t nonce[AEGIS_NONCE_LEN])
{
    __m128i k  = load128u(key);
    __m128i n  = load128u(nonce);
    __m128i kn = xor128(k, n);
    __m128i C0 = load128u(C0_bytes);
    __m128i C1 = load128u(C1_bytes);

    st->S[0] = kn;
    st->S[1] = C1;
    st->S[2] = C0;
    st->S[3] = k;
    st->S[4] = kn;

    /* 10-round initialization */
    for (int i = 0; i < 10; i++) {
        state_update128(st->S, (i % 2 == 0) ? kn : k);
    }
}

void aegis128_x86_ad_update(aegis128_x86_state_t *st,
                            const uint8_t *ad, size_t adlen)
{
    size_t i;
    for (i = 0; i + 16 <= adlen; i += 16) {
        state_update128(st->S, load128(ad + i));
    }
    size_t rem = adlen - i;
    if (rem > 0) {
        uint8_t pad[16] = {0};
        memcpy(pad, ad + i, rem);
        state_update128(st->S, load128u(pad));
    }
}

void aegis128_x86_enc_update(aegis128_x86_state_t *st,
                              uint8_t *dst, const uint8_t *src, size_t len)
{
    for (size_t i = 0; i < len; i += 16) {
        __m128i ks = key_stream(st->S);
        __m128i pt = load128(src + i);
        __m128i ct = xor128(pt, ks);
        store128(dst + i, ct);
        state_update128(st->S, pt);
    }
}

void aegis128_x86_enc_final(aegis128_x86_state_t *st,
                             uint8_t *dst, const uint8_t *src, size_t len,
                             uint8_t tag[AEGIS_TAG_LEN])
{
    size_t full = len & ~(size_t)15;
    for (size_t i = 0; i < full; i += 16) {
        __m128i ks = key_stream(st->S);
        __m128i pt = load128(src + i);
        store128(dst + i, xor128(pt, ks));
        state_update128(st->S, pt);
    }

    size_t rem = len - full;
    if (rem > 0) {
        uint8_t pad[16] = {0};
        memcpy(pad, src + full, rem);
        __m128i ks = key_stream(st->S);
        __m128i pt = load128u(pad);
        __m128i ct = xor128(pt, ks);
        uint8_t ct_buf[16];
        store128u(ct_buf, ct);
        memcpy(dst + full, ct_buf, rem);
        state_update128(st->S, pt);
    }

    /* Tag: 7 rounds */
    __m128i tmp = xor128(xor128(xor128(xor128(st->S[0], st->S[1]),
                                       st->S[2]), st->S[3]), st->S[4]);

    for (int i = 0; i < 7; i++) {
        state_update128(st->S, tmp);
        tmp = xor128(xor128(xor128(xor128(st->S[0], st->S[1]),
                                   st->S[2]), st->S[3]), st->S[4]);
    }

    store128u(tag, tmp);
}

void aegis128_x86_dec_update(aegis128_x86_state_t *st,
                              uint8_t *dst, const uint8_t *src, size_t len)
{
    for (size_t i = 0; i < len; i += 16) {
        __m128i ks = key_stream(st->S);
        __m128i ct = load128(src + i);
        __m128i pt = xor128(ct, ks);
        store128(dst + i, pt);
        state_update128(st->S, pt);
    }
}

int aegis128_x86_dec_final(aegis128_x86_state_t *st,
                            uint8_t *dst, const uint8_t *src, size_t len,
                            const uint8_t tag[AEGIS_TAG_LEN])
{
    size_t full = len & ~(size_t)15;
    for (size_t i = 0; i < full; i += 16) {
        __m128i ks = key_stream(st->S);
        __m128i ct = load128(src + i);
        __m128i pt = xor128(ct, ks);
        store128(dst + i, pt);
        state_update128(st->S, pt);
    }

    size_t rem = len - full;
    if (rem > 0) {
        uint8_t pad[16] = {0};
        uint8_t ct_buf[16] = {0};
        memcpy(ct_buf, src + full, rem);
        __m128i ks = key_stream(st->S);
        __m128i ct = load128u(ct_buf);
        __m128i pt = xor128(ct, ks);
        uint8_t pt_buf[16];
        store128u(pt_buf, pt);
        memcpy(dst + full, pt_buf, rem);
        memcpy(pad, dst + full, rem);
        state_update128(st->S, load128u(pad));
    }

    /* Compute expected tag */
    __m128i tmp = xor128(xor128(xor128(xor128(st->S[0], st->S[1]),
                                       st->S[2]), st->S[3]), st->S[4]);

    for (int i = 0; i < 7; i++) {
        state_update128(st->S, tmp);
        tmp = xor128(xor128(xor128(xor128(st->S[0], st->S[1]),
                                   st->S[2]), st->S[3]), st->S[4]);
    }

    uint8_t expected_tag[AEGIS_TAG_LEN];
    store128u(expected_tag, tmp);

    /* Constant-time comparison */
    uint8_t diff = 0;
    for (int i = 0; i < AEGIS_TAG_LEN; i++) {
        diff |= (expected_tag[i] ^ tag[i]);
    }

    if (diff != 0) {
        if (len > 0 && dst != NULL) {
            volatile uint8_t *p = (volatile uint8_t *)dst;
            for (size_t i = 0; i < len; i++) p[i] = 0;
        }
        return -1;
    }
    return 0;
}

/* ════════════════════════════════════════════════════════════════
 * One-shot API
 * ════════════════════════════════════════════════════════════════ */

void aegis128_x86_encrypt(uint8_t *c, uint8_t tag[AEGIS_TAG_LEN],
                          const uint8_t *m, size_t mlen,
                          const uint8_t *ad, size_t adlen,
                          const uint8_t nonce[AEGIS_NONCE_LEN],
                          const uint8_t key[AEGIS_KEY_LEN])
{
    aegis128_x86_state_t st;
    aegis128_x86_init(&st, key, nonce);
    if (adlen > 0) aegis128_x86_ad_update(&st, ad, adlen);

    size_t full = mlen & ~(size_t)15;
    if (full > 0) aegis128_x86_enc_update(&st, c, m, full);

    aegis128_x86_enc_final(&st, c + full, m + full, mlen - full, tag);
}

int aegis128_x86_decrypt(uint8_t *m,
                         const uint8_t *c, size_t clen,
                         const uint8_t *ad, size_t adlen,
                         const uint8_t nonce[AEGIS_NONCE_LEN],
                         const uint8_t key[AEGIS_KEY_LEN],
                         const uint8_t tag[AEGIS_TAG_LEN])
{
    aegis128_x86_state_t st;
    aegis128_x86_init(&st, key, nonce);
    if (adlen > 0) aegis128_x86_ad_update(&st, ad, adlen);

    size_t full = clen & ~(size_t)15;
    if (full > 0) aegis128_x86_dec_update(&st, m, c, full);

    return aegis128_x86_dec_final(&st, m + full, c + full, clen - full, tag);
}

#endif /* __x86_64__ */
