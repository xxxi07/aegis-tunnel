/*
 * aegis.c — Pure C99 implementation of AEGIS-128 AEAD
 *
 * Implements the AEGIS-128 authenticated encryption algorithm as
 * specified in the IETF CFRG draft-irtf-cfrg-aegis-aead.
 *
 * AEGIS-128 uses 5 × 128-bit state words with the AES round function
 * (SubBytes + ShiftRows + MixColumns) as its core permutation.
 *
 * The state update function State_Update128 applies 5 AES rounds in
 * a chained XOR pattern that provides both diffusion and confusion:
 *
 *   S'[0] = AES_ROUND(S[4]) ⊕ S[0] ⊕ m
 *   S'[1] = AES_ROUND(S[0]) ⊕ S[1]
 *   S'[2] = AES_ROUND(S[1]) ⊕ S[2]
 *   S'[3] = AES_ROUND(S[2]) ⊕ S[3]
 *   S'[4] = AES_ROUND(S[3]) ⊕ S[4]
 *
 * CRITICAL: The computation must use OLD state values throughout.
 * We use a temporary array to avoid overwriting values that later
 * rounds still need.
 */

#include "crypto/aegis.h"
#include <string.h>

/* ════════════════════════════════════════════════════════════════
 * AES Building Blocks
 * ════════════════════════════════════════════════════════════════ */

/* Standard AES S-Box (256 bytes) */
static const uint8_t aes_sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

/* ─── GF(2^8) multiplication helpers for MixColumns ────────────── */

/* Multiply by 2 in GF(2^8) with reduction polynomial x^8+x^4+x^3+x+1 */
static uint8_t xtime(uint8_t x)
{
    return (uint8_t)((uint8_t)(x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

/* Multiply by 3 in GF(2^8) */
static uint8_t mul3(uint8_t x)
{
    return xtime(x) ^ x;
}

/* ─── AES SubBytes ─────────────────────────────────────────────── */

static void aes_sub_bytes(uint8_t block[16])
{
    for (int i = 0; i < 16; i++) {
        block[i] = aes_sbox[block[i]];
    }
}

/* ─── AES ShiftRows ────────────────────────────────────────────── */
/*
 * AES state is column-major:
 *   [ 0  4  8 12 ]     [ 0  4  8 12 ]
 *   [ 1  5  9 13 ]  →  [ 5  9 13  1 ]   (row 1: shift left by 1)
 *   [ 2  6 10 14 ]     [10 14  2  6 ]   (row 2: shift left by 2)
 *   [ 3  7 11 15 ]     [15  3  7 11 ]   (row 3: shift left by 3)
 *
 * Output byte i comes from input byte perm[i].
 */
static const uint8_t sr_perm[16] = {
    0,  5, 10, 15,   /* row 0 (no shift), then col 0 of other rows */
    4,  9, 14,  3,   /* row 1 shifted: bytes 4,9,14,3 */
    8, 13,  2,  7,   /* row 2 shifted: bytes 8,13,2,7 */
   12,  1,  6, 11    /* row 3 shifted: bytes 12,1,6,11 */
};

static void aes_shift_rows(uint8_t block[16])
{
    uint8_t tmp[16];
    for (int i = 0; i < 16; i++) {
        tmp[i] = block[sr_perm[i]];
    }
    memcpy(block, tmp, 16);
}

/* ─── AES MixColumns ───────────────────────────────────────────── */
/*
 * Each column [a0, a1, a2, a3] transforms to:
 *   b0 = 2*a0 ⊕ 3*a1 ⊕ 1*a2 ⊕ 1*a3
 *   b1 = 1*a0 ⊕ 2*a1 ⊕ 3*a2 ⊕ 1*a3
 *   b2 = 1*a0 ⊕ 1*a1 ⊕ 2*a2 ⊕ 3*a3
 *   b3 = 3*a0 ⊕ 1*a1 ⊕ 1*a2 ⊕ 2*a3
 *
 * In the column-major layout, bytes 0-3 form column 0, bytes 4-7
 * form column 1, etc.  We process all 4 columns identically.
 */
static void aes_mix_columns(uint8_t block[16])
{
    for (int c = 0; c < 4; c++) {
        /* column start index */
        int i = c * 4;
        uint8_t a0 = block[i + 0];
        uint8_t a1 = block[i + 1];
        uint8_t a2 = block[i + 2];
        uint8_t a3 = block[i + 3];

        block[i + 0] = xtime(a0) ^ mul3(a1) ^ a2 ^ a3;
        block[i + 1] = a0 ^ xtime(a1) ^ mul3(a2) ^ a3;
        block[i + 2] = a0 ^ a1 ^ xtime(a2) ^ mul3(a3);
        block[i + 3] = mul3(a0) ^ a1 ^ a2 ^ xtime(a3);
    }
}

/* ─── Full AES round (no round key — AEGIS uses keyless rounds) ── */

static void aes_round(uint8_t block[16])
{
    aes_sub_bytes(block);
    aes_shift_rows(block);
    aes_mix_columns(block);
}

/* ─── XOR five 16-byte blocks together into out ────────────────── */

static void xor5_blocks(uint8_t out[16],
                        const uint8_t a[16], const uint8_t b[16],
                        const uint8_t c[16], const uint8_t d[16],
                        const uint8_t e[16])
{
    for (int i = 0; i < 16; i++) {
        out[i] = a[i] ^ b[i] ^ c[i] ^ d[i] ^ e[i];
    }
}

/* ════════════════════════════════════════════════════════════════
 * AEGIS-128 State Update (the heart of the algorithm)
 * ════════════════════════════════════════════════════════════════ */

/*
 * State_Update128(S, m):
 *
 *   new_S[0] = AES_ROUND(S[4]) ⊕ S[0] ⊕ m
 *   new_S[1] = AES_ROUND(S[0]) ⊕ S[1]
 *   new_S[2] = AES_ROUND(S[1]) ⊕ S[2]
 *   new_S[3] = AES_ROUND(S[2]) ⊕ S[3]
 *   new_S[4] = AES_ROUND(S[3]) ⊕ S[4]
 *
 * CRITICAL: All AES rounds read from OLD state values.
 * We compute into a temporary array then copy back.
 */
static void state_update128(uint8_t S[5][16], const uint8_t m[16])
{
    uint8_t new_S[5][16];
    uint8_t tmp[16];

    /* new_S[0] = AES_ROUND(S[4]) ⊕ S[0] ⊕ m */
    memcpy(tmp, S[4], 16);
    aes_round(tmp);
    for (int i = 0; i < 16; i++) {
        new_S[0][i] = tmp[i] ^ S[0][i] ^ m[i];
    }

    /* new_S[1] = AES_ROUND(S[0]) ⊕ S[1] */
    memcpy(tmp, S[0], 16);
    aes_round(tmp);
    for (int i = 0; i < 16; i++) {
        new_S[1][i] = tmp[i] ^ S[1][i];
    }

    /* new_S[2] = AES_ROUND(S[1]) ⊕ S[2] */
    memcpy(tmp, S[1], 16);
    aes_round(tmp);
    for (int i = 0; i < 16; i++) {
        new_S[2][i] = tmp[i] ^ S[2][i];
    }

    /* new_S[3] = AES_ROUND(S[2]) ⊕ S[3] */
    memcpy(tmp, S[2], 16);
    aes_round(tmp);
    for (int i = 0; i < 16; i++) {
        new_S[3][i] = tmp[i] ^ S[3][i];
    }

    /* new_S[4] = AES_ROUND(S[3]) ⊕ S[4] */
    memcpy(tmp, S[3], 16);
    aes_round(tmp);
    for (int i = 0; i < 16; i++) {
        new_S[4][i] = tmp[i] ^ S[4][i];
    }

    /* Copy back */
    memcpy(S, new_S, sizeof(new_S));
}

/* ════════════════════════════════════════════════════════════════
 * AEGIS-128 Constants (Fibonacci sequence based)
 * ════════════════════════════════════════════════════════════════ */

/*
 * C0 and C1 are 128-bit constants derived from the Fibonacci sequence.
 * From the AEGIS specification (CAESAR submission):
 */
static const uint8_t C0[16] = {
    0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d,
    0x15, 0x22, 0x33, 0x59, 0x90, 0xe9, 0x62, 0x62
};

static const uint8_t C1[16] = {
    0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1,
    0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd
};

/* ════════════════════════════════════════════════════════════════
 * Key stream extraction
 * ════════════════════════════════════════════════════════════════ */

/*
 * AEGIS-128 encryption keystream:
 *   ks = S[1] ⊕ S[4] ⊕ (S[2] & S[3])
 *
 * ciphertext = plaintext ⊕ ks
 * plaintext  = ciphertext ⊕ ks
 */
static void key_stream(uint8_t ks[16], uint8_t S[5][16])
{
    for (int i = 0; i < 16; i++) {
        ks[i] = S[1][i] ^ S[4][i] ^ (S[2][i] & S[3][i]);
    }
}

/* ─── Process one full 16-byte block (encrypt direction) ──────── */
static void process_enc_block(uint8_t S[5][16],
                              uint8_t *dst, const uint8_t *src)
{
    uint8_t ks[16];
    key_stream(ks, S);

    if (dst == src) {
        /* In-place: save plaintext before overwriting with ciphertext */
        uint8_t pt[16];
        memcpy(pt, src, 16);
        for (int i = 0; i < 16; i++) {
            dst[i] = pt[i] ^ ks[i];
        }
        state_update128(S, pt);
    } else {
        for (int i = 0; i < 16; i++) {
            dst[i] = src[i] ^ ks[i];
        }
        state_update128(S, src);
    }
}

/* ─── Process one full 16-byte block (decrypt direction) ──────── */
static void process_dec_block(uint8_t S[5][16],
                              uint8_t *dst, const uint8_t *src)
{
    uint8_t ks[16];
    key_stream(ks, S);

    /* plaintext = ciphertext ⊕ keystream */
    for (int i = 0; i < 16; i++) {
        dst[i] = src[i] ^ ks[i];
    }

    /* State_Update128 with recovered plaintext as message */
    state_update128(S, dst);
}

/* ════════════════════════════════════════════════════════════════
 * Streaming API Implementation
 * ════════════════════════════════════════════════════════════════ */

void aegis_init(aegis_state_t *st,
                const uint8_t key[AEGIS_KEY_LEN],
                const uint8_t nonce[AEGIS_NONCE_LEN])
{
    uint8_t kn[16]; /* key ^ nonce */

    /* kn = key ^ nonce */
    for (int i = 0; i < 16; i++) {
        kn[i] = key[i] ^ nonce[i];
    }

    /*
     * Initial state:
     *   S[0] = key ^ nonce
     *   S[1] = C1
     *   S[2] = C0
     *   S[3] = key
     *   S[4] = key ^ nonce
     */
    memcpy(st->S[0], kn, 16);
    memcpy(st->S[1], C1, 16);
    memcpy(st->S[2], C0, 16);
    memcpy(st->S[3], key, 16);
    memcpy(st->S[4], kn, 16);

    /*
     * 10-round initialization:
     *   Round 0, 2, 4, 6, 8:  State_Update128(S, kn)
     *   Round 1, 3, 5, 7, 9:  State_Update128(S, key)
     */
    for (int i = 0; i < 10; i++) {
        if (i % 2 == 0) {
            state_update128(st->S, kn);
        } else {
            state_update128(st->S, key);
        }
    }
}

void aegis_ad_update(aegis_state_t *st,
                     const uint8_t *ad, size_t adlen)
{
    size_t i;

    /* Process full 16-byte blocks */
    for (i = 0; i + 16 <= adlen; i += 16) {
        state_update128(st->S, ad + i);
    }

    /* Process final partial block (padded with zeros) */
    size_t rem = adlen - i;
    if (rem > 0) {
        uint8_t pad[16];
        memset(pad, 0, 16);
        memcpy(pad, ad + i, rem);
        state_update128(st->S, pad);
    }
}

void aegis_enc_update(aegis_state_t *st,
                      uint8_t *dst, const uint8_t *src, size_t len)
{
    /*
     * Caller guarantees len is a multiple of 16, or this is the
     * non-final data (len % 16 == 0 for all but the last call).
     */
    for (size_t i = 0; i < len; i += 16) {
        process_enc_block(st->S, dst + i, src + i);
    }
}

void aegis_enc_final(aegis_state_t *st,
                     uint8_t *dst, const uint8_t *src, size_t len,
                     uint8_t tag[AEGIS_TAG_LEN])
{
    /*
     * Process remaining data.
     * Full 16-byte blocks are processed normally.
     * The final partial block (0..15 bytes) is zero-padded.
     */
    size_t full = len & ~(size_t)15;
    for (size_t i = 0; i < full; i += 16) {
        uint8_t ks[16];
        key_stream(ks, st->S);
        for (size_t j = 0; j < 16; j++)
            dst[i + j] = src[i + j] ^ ks[j];
        state_update128(st->S, src + i);
    }

    size_t rem = len - full;
    if (rem > 0) {
        uint8_t pad[16];
        memset(pad, 0, 16);
        memcpy(pad, src + full, rem);

        uint8_t ks[16];
        key_stream(ks, st->S);
        for (size_t i = 0; i < rem; i++)
            dst[full + i] = src[full + i] ^ ks[i];

        state_update128(st->S, pad);
    }

    /*
     * Tag generation (7 rounds).
     *
     * From the IETF CFRG draft (Section 5.2):
     *   tmp = S[0] ⊕ S[1] ⊕ S[2] ⊕ S[3] ⊕ S[4]
     *   Repeat 7 times:
     *       State_Update128(S, tmp)
     *       tmp = S[0] ⊕ S[1] ⊕ S[2] ⊕ S[3] ⊕ S[4]
     *   tag = tmp
     */
    uint8_t tmp[16];
    xor5_blocks(tmp, st->S[0], st->S[1], st->S[2], st->S[3], st->S[4]);

    for (int i = 0; i < 7; i++) {
        state_update128(st->S, tmp);
        xor5_blocks(tmp, st->S[0], st->S[1], st->S[2], st->S[3], st->S[4]);
    }

    memcpy(tag, tmp, AEGIS_TAG_LEN);
}

void aegis_dec_update(aegis_state_t *st,
                      uint8_t *dst, const uint8_t *src, size_t len)
{
    for (size_t i = 0; i < len; i += 16) {
        process_dec_block(st->S, dst + i, src + i);
    }
}

int aegis_dec_final(aegis_state_t *st,
                    uint8_t *dst, const uint8_t *src, size_t len,
                    const uint8_t tag[AEGIS_TAG_LEN])
{
    /*
     * Process remaining data.
     * Full 16-byte blocks are processed normally.
     * The final partial block (0..15 bytes) is zero-padded.
     */
    size_t full = len & ~(size_t)15;
    for (size_t i = 0; i < full; i += 16) {
        uint8_t ks[16];
        key_stream(ks, st->S);
        for (size_t j = 0; j < 16; j++)
            dst[i + j] = src[i + j] ^ ks[j];
        state_update128(st->S, dst + i);
    }

    size_t rem = len - full;
    if (rem > 0) {
        uint8_t pad[16];
        memset(pad, 0, 16);
        uint8_t ks[16];
        key_stream(ks, st->S);
        for (size_t i = 0; i < rem; i++)
            dst[full + i] = src[full + i] ^ ks[i];
        memcpy(pad, dst + full, rem);
        state_update128(st->S, pad);
    }

    /*
     * Compute expected tag.
     * Same 7-round procedure as encryption.
     */
    uint8_t expected_tag[AEGIS_TAG_LEN];
    uint8_t tmp[16];
    xor5_blocks(tmp, st->S[0], st->S[1], st->S[2], st->S[3], st->S[4]);

    for (int i = 0; i < 7; i++) {
        state_update128(st->S, tmp);
        xor5_blocks(tmp, st->S[0], st->S[1], st->S[2], st->S[3], st->S[4]);
    }

    memcpy(expected_tag, tmp, AEGIS_TAG_LEN);

    /*
     * Constant-time tag comparison.
     * We use a bitwise-OR-of-XORs accumulator. No early exit.
     */
    uint8_t diff = 0;
    for (int i = 0; i < AEGIS_TAG_LEN; i++) {
        diff |= (expected_tag[i] ^ tag[i]);
    }

    /*
     * On mismatch: zero the output plaintext and return error.
     * The constant-time check ensures no timing side-channel.
     */
    if (diff != 0) {
        /* Zero all outputs that may contain sensitive data */
        if (len > 0 && dst != NULL) {
            volatile uint8_t *p = (volatile uint8_t *)dst;
            for (size_t i = 0; i < len; i++) {
                p[i] = 0;
            }
        }
        return -1;
    }

    return 0;
}

/* ════════════════════════════════════════════════════════════════
 * One-shot API Implementation
 * ════════════════════════════════════════════════════════════════ */

void aegis_encrypt(uint8_t *c, uint8_t tag[AEGIS_TAG_LEN],
                   const uint8_t *m, size_t mlen,
                   const uint8_t *ad, size_t adlen,
                   const uint8_t nonce[AEGIS_NONCE_LEN],
                   const uint8_t key[AEGIS_KEY_LEN])
{
    aegis_state_t st;

    aegis_init(&st, key, nonce);

    if (adlen > 0) {
        aegis_ad_update(&st, ad, adlen);
    }

    /* Process full blocks */
    size_t full_blocks = mlen & ~(size_t)15;  /* mlen - (mlen % 16) */
    if (full_blocks > 0) {
        aegis_enc_update(&st, c, m, full_blocks);
    }

    /* Process final partial block + generate tag */
    size_t rem = mlen - full_blocks;
    aegis_enc_final(&st,
                    c + full_blocks,
                    m + full_blocks,
                    rem,
                    tag);
}

int aegis_decrypt(uint8_t *m,
                  const uint8_t *c, size_t clen,
                  const uint8_t *ad, size_t adlen,
                  const uint8_t nonce[AEGIS_NONCE_LEN],
                  const uint8_t key[AEGIS_KEY_LEN],
                  const uint8_t tag[AEGIS_TAG_LEN])
{
    aegis_state_t st;

    aegis_init(&st, key, nonce);

    if (adlen > 0) {
        aegis_ad_update(&st, ad, adlen);
    }

    /* Process full blocks */
    size_t full_blocks = clen & ~(size_t)15;
    if (full_blocks > 0) {
        aegis_dec_update(&st, m, c, full_blocks);
    }

    /* Process final partial block + verify tag */
    size_t rem = clen - full_blocks;
    return aegis_dec_final(&st,
                           m + full_blocks,
                           c + full_blocks,
                           rem,
                           tag);
}
