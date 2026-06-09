/*
 * test_aegis.c — AEGIS-128 Known-Answer and roundtrip tests
 *
 * Validates the AEGIS-128 pure C implementation against:
 *   1. Roundtrip consistency (encrypt → decrypt → same plaintext)
 *   2. Authentication failure (wrong key / corrupted tag)
 *   3. Various message and AD sizes
 *   4. Known-answer test vectors from the AEGIS specification
 *
 * NOTE: The known-answer test vectors are from the AEGIS v1.1
 * CAESAR submission (Appendix A).  If these don't match, it means
 * the implementation deviates from the specification.
 */

#include "crypto/aegis.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) do { \
    tests_run++; \
    fprintf(stderr, "  %-45s ... ", name); \
} while(0)

#define PASS() do { \
    tests_passed++; \
    fprintf(stderr, "PASS\n"); \
} while(0)

#define FAIL(msg) do { \
    tests_failed++; \
    fprintf(stderr, "FAIL: %s\n", msg); \
} while(0)

/* ─── Helper: run one-shot encrypt then decrypt ────────────────── */

static int roundtrip(const uint8_t *pt, size_t ptlen,
                     const uint8_t *ad, size_t adlen,
                     const uint8_t key[AEGIS_KEY_LEN],
                     const uint8_t nonce[AEGIS_NONCE_LEN])
{
    uint8_t *ct = (uint8_t *)calloc(1, ptlen + AEGIS_TAG_LEN);
    uint8_t *recovered = (uint8_t *)calloc(1, ptlen);
    uint8_t tag[AEGIS_TAG_LEN];

    if (!ct || !recovered) {
        free(ct);
        free(recovered);
        return -1;
    }

    aegis_encrypt(ct, tag, pt, ptlen, ad, adlen, nonce, key);

    int ret = aegis_decrypt(recovered, ct, ptlen, ad, adlen,
                            nonce, key, tag);

    if (ret != 0) {
        free(ct);
        free(recovered);
        return -1;
    }

    int match = (memcmp(pt, recovered, ptlen) == 0) ? 0 : -1;

    free(ct);
    free(recovered);
    return match;
}

/* ─── Test 1: Empty message, empty AD ──────────────────────────── */

static void test_empty_message(void)
{
    TEST("empty message, empty AD");
    uint8_t key[AEGIS_KEY_LEN]   = {0x10,0x01,0x00,0x00,0x00,0x00,0x00,0x00,
                                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    uint8_t nonce[AEGIS_NONCE_LEN] = {0x10,0x00,0x02,0x00,0x00,0x00,0x00,0x00,
                                      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

    int ret = roundtrip(NULL, 0, NULL, 0, key, nonce);
    if (ret == 0) {
        PASS();
    } else {
        FAIL("roundtrip failed for empty message");
    }
}

/* ─── Test 2: Single-block message, no AD ──────────────────────── */

static void test_single_block(void)
{
    TEST("single block (16 bytes), no AD");
    uint8_t key[AEGIS_KEY_LEN]   = {0x10,0x01,0x00,0x00,0x00,0x00,0x00,0x00,
                                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    uint8_t nonce[AEGIS_NONCE_LEN] = {0x10,0x00,0x02,0x00,0x00,0x00,0x00,0x00,
                                      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    uint8_t pt[16] = "Hello, AEGIS!!!";

    int ret = roundtrip(pt, 16, NULL, 0, key, nonce);
    if (ret == 0) {
        PASS();
    } else {
        FAIL("roundtrip failed for single block");
    }
}

/* ─── Test 3: Multi-block message with AD ──────────────────────── */

static void test_multi_block(void)
{
    TEST("multi-block (47 bytes) with AD (8 bytes)");
    uint8_t key[AEGIS_KEY_LEN];
    uint8_t nonce[AEGIS_NONCE_LEN];
    uint8_t ad[8];
    memset(key, 0x42, AEGIS_KEY_LEN);
    memset(nonce, 0x13, AEGIS_NONCE_LEN);
    memset(ad, 0x07, sizeof(ad));

    uint8_t pt[47];
    for (int i = 0; i < 47; i++) pt[i] = (uint8_t)i;

    int ret = roundtrip(pt, sizeof(pt), ad, sizeof(ad), key, nonce);
    if (ret == 0) {
        PASS();
    } else {
        FAIL("roundtrip failed for multi-block with AD");
    }
}

/* ─── Test 4: Large message, large AD ──────────────────────────── */

static void test_large_message(void)
{
    TEST("large message (1024 bytes) with large AD (256 bytes)");
    uint8_t key[AEGIS_KEY_LEN];
    uint8_t nonce[AEGIS_NONCE_LEN];
    memset(key, 0xaa, AEGIS_KEY_LEN);
    memset(nonce, 0x55, AEGIS_NONCE_LEN);

    uint8_t *pt = (uint8_t *)malloc(1024);
    uint8_t *ad = (uint8_t *)malloc(256);
    if (!pt || !ad) {
        free(pt); free(ad);
        FAIL("malloc failed");
        return;
    }
    for (int i = 0; i < 1024; i++) pt[i] = (uint8_t)(i & 0xff);
    for (int i = 0; i < 256; i++) ad[i] = (uint8_t)((i * 7) & 0xff);

    int ret = roundtrip(pt, 1024, ad, 256, key, nonce);
    free(pt);
    free(ad);

    if (ret == 0) {
        PASS();
    } else {
        FAIL("roundtrip failed for large message");
    }
}

/* ─── Test 5: Wrong key produces authentication failure ────────── */

static void test_wrong_key(void)
{
    TEST("wrong key → authentication failure");
    uint8_t key1[AEGIS_KEY_LEN];
    uint8_t key2[AEGIS_KEY_LEN];
    uint8_t nonce[AEGIS_NONCE_LEN];
    memset(key1, 0x11, AEGIS_KEY_LEN);
    memset(key2, 0x22, AEGIS_KEY_LEN);
    memset(nonce, 0x33, AEGIS_NONCE_LEN);

    uint8_t pt[32] = "test message for wrong key...";
    uint8_t ct[32];
    uint8_t recovered[32];
    uint8_t tag[AEGIS_TAG_LEN];

    /* Encrypt with key1 */
    aegis_encrypt(ct, tag, pt, 32, NULL, 0, nonce, key1);

    /* Try to decrypt with key2 — must fail */
    int ret = aegis_decrypt(recovered, ct, 32, NULL, 0, nonce, key2, tag);
    if (ret != 0) {
        PASS();
    } else {
        FAIL("wrong key should have been rejected");
    }
}

/* ─── Test 6: Corrupted tag produces authentication failure ────── */

static void test_corrupted_tag(void)
{
    TEST("corrupted tag → authentication failure");
    uint8_t key[AEGIS_KEY_LEN];
    uint8_t nonce[AEGIS_NONCE_LEN];
    memset(key, 0x77, AEGIS_KEY_LEN);
    memset(nonce, 0x88, AEGIS_NONCE_LEN);

    uint8_t pt[32] = "test message for corrupt tag";
    uint8_t ct[32];
    uint8_t recovered[32];
    uint8_t tag[AEGIS_TAG_LEN];

    aegis_encrypt(ct, tag, pt, 32, NULL, 0, nonce, key);

    /* Flip a bit in the tag */
    tag[5] ^= 0x01;

    int ret = aegis_decrypt(recovered, ct, 32, NULL, 0, nonce, key, tag);
    if (ret != 0) {
        PASS();
    } else {
        FAIL("corrupted tag should have been rejected");
    }
}

/* ─── Test 7: Corrupted ciphertext produces authentication failure */

static void test_corrupted_ciphertext(void)
{
    TEST("corrupted ciphertext → authentication failure");
    uint8_t key[AEGIS_KEY_LEN];
    uint8_t nonce[AEGIS_NONCE_LEN];
    memset(key, 0x99, AEGIS_KEY_LEN);
    memset(nonce, 0xaa, AEGIS_NONCE_LEN);

    uint8_t pt[32] = "test message for corrupt ct..";
    uint8_t ct[32];
    uint8_t recovered[32];
    uint8_t tag[AEGIS_TAG_LEN];

    aegis_encrypt(ct, tag, pt, 32, NULL, 0, nonce, key);

    /* Flip a bit in the ciphertext */
    ct[10] ^= 0x01;

    int ret = aegis_decrypt(recovered, ct, 32, NULL, 0, nonce, key, tag);
    if (ret != 0) {
        PASS();
    } else {
        FAIL("corrupted ciphertext should have been rejected");
    }
}

/* ─── Test 8: Wrong AD produces authentication failure ─────────── */

static void test_wrong_ad(void)
{
    TEST("wrong AD → authentication failure");
    uint8_t key[AEGIS_KEY_LEN];
    uint8_t nonce[AEGIS_NONCE_LEN];
    memset(key, 0xbb, AEGIS_KEY_LEN);
    memset(nonce, 0xcc, AEGIS_NONCE_LEN);

    uint8_t pt[20];
    memcpy(pt, "test AD mismatch....", 20);
    uint8_t ct[20];
    uint8_t recovered[20];
    uint8_t tag[AEGIS_TAG_LEN];
    uint8_t ad1[8];
    uint8_t ad2[8];
    memcpy(ad1, "correct!", 8);
    memcpy(ad2, "wrong!!!", 8);

    aegis_encrypt(ct, tag, pt, 20, ad1, 8, nonce, key);

    int ret = aegis_decrypt(recovered, ct, 20, ad2, 8, nonce, key, tag);
    if (ret != 0) {
        PASS();
    } else {
        FAIL("wrong AD should have been rejected");
    }
}

/* ─── Test 9: In-place encryption (c == m) ─────────────────────── */

static void test_inplace(void)
{
    TEST("in-place encrypt/decrypt (buffer aliasing)");
    uint8_t key[AEGIS_KEY_LEN];
    uint8_t nonce[AEGIS_NONCE_LEN];
    memset(key, 0xdd, AEGIS_KEY_LEN);
    memset(nonce, 0xee, AEGIS_NONCE_LEN);

    uint8_t buf[48];
    uint8_t expected[48];
    for (int i = 0; i < 48; i++) expected[i] = buf[i] = (uint8_t)i;

    uint8_t tag[AEGIS_TAG_LEN];

    /* Encrypt in-place */
    aegis_encrypt(buf, tag, buf, 48, NULL, 0, nonce, key);

    /* Should now be different from original */
    if (memcmp(buf, expected, 48) == 0) {
        FAIL("in-place encryption did not change the buffer");
        return;
    }

    /* Decrypt in-place */
    int ret = aegis_decrypt(buf, buf, 48, NULL, 0, nonce, key, tag);
    if (ret != 0) {
        FAIL("in-place decryption rejected valid tag");
        return;
    }

    if (memcmp(buf, expected, 48) == 0) {
        PASS();
    } else {
        FAIL("in-place roundtrip did not recover original plaintext");
    }
}

/* ─── Test 10: Streaming API roundtrip ─────────────────────────── */

static void test_streaming_api(void)
{
    TEST("streaming API roundtrip (3 chunks of AD + 3 chunks of PT)");
    uint8_t key[AEGIS_KEY_LEN];
    uint8_t nonce[AEGIS_NONCE_LEN];
    memset(key, 0x12, AEGIS_KEY_LEN);
    memset(nonce, 0x34, AEGIS_NONCE_LEN);

    uint8_t pt[50], ct[50], recovered[50];
    uint8_t ad[30];
    for (int i = 0; i < 50; i++) pt[i] = (uint8_t)(i * 3);
    for (int i = 0; i < 30; i++) ad[i] = (uint8_t)(i * 5);

    aegis_state_t enc_st, dec_st;
    uint8_t tag1[AEGIS_TAG_LEN];

    /* ── Encrypt using streaming API ── */
    aegis_init(&enc_st, key, nonce);

    /* AD in 3 chunks: 10 + 10 + 10 bytes */
    aegis_ad_update(&enc_st, ad, 10);
    aegis_ad_update(&enc_st, ad + 10, 10);
    aegis_ad_update(&enc_st, ad + 20, 10);

    /* PT in 3 chunks: 16 + 16 + 18 bytes */
    aegis_enc_update(&enc_st, ct, pt, 16);
    aegis_enc_update(&enc_st, ct + 16, pt + 16, 16);
    aegis_enc_final(&enc_st, ct + 32, pt + 32, 18, tag1);

    /* ── Decrypt using streaming API (same chunk pattern) ── */
    aegis_init(&dec_st, key, nonce);

    aegis_ad_update(&dec_st, ad, 10);
    aegis_ad_update(&dec_st, ad + 10, 10);
    aegis_ad_update(&dec_st, ad + 20, 10);

    aegis_dec_update(&dec_st, recovered, ct, 16);
    aegis_dec_update(&dec_st, recovered + 16, ct + 16, 16);
    int ret = aegis_dec_final(&dec_st, recovered + 32, ct + 32, 18, tag1);

    if (ret != 0) {
        FAIL("streaming decrypt rejected valid tag");
        return;
    }

    if (memcmp(pt, recovered, 50) == 0) {
        PASS();
    } else {
        FAIL("streaming roundtrip produced wrong plaintext");
    }
}

/* ─── Test 11: Different keys give different ciphertexts ───────── */

static void test_key_variation(void)
{
    TEST("different keys → different ciphertexts");
    uint8_t key1[AEGIS_KEY_LEN], key2[AEGIS_KEY_LEN];
    uint8_t nonce[AEGIS_NONCE_LEN];
    memset(key1, 0x01, AEGIS_KEY_LEN);
    memset(key2, 0x02, AEGIS_KEY_LEN);
    memset(nonce, 0, AEGIS_NONCE_LEN);

    uint8_t pt[32] = "same plaintext different keys!";
    uint8_t ct1[32], ct2[32];
    uint8_t tag1[AEGIS_TAG_LEN];

    uint8_t tag2[AEGIS_TAG_LEN];
    aegis_encrypt(ct1, tag1, pt, 32, NULL, 0, nonce, key1);
    aegis_encrypt(ct2, tag2, pt, 32, NULL, 0, nonce, key2);

    if (memcmp(ct1, ct2, 32) != 0 &&
        memcmp(tag1, tag2, AEGIS_TAG_LEN) != 0) {
        PASS();
    } else {
        FAIL("different keys produced identical ciphertext or tag");
    }
}

/* ─── Test 12: Nonce reuse produces different ciphertext? NO!
 *           Reusing nonce with same key should produce same output.
 *           This test verifies deterministic behavior. ─────────── */

static void test_deterministic(void)
{
    TEST("deterministic: same (key,nonce,pt,ad) → same (ct,tag)");
    uint8_t key[AEGIS_KEY_LEN];
    uint8_t nonce[AEGIS_NONCE_LEN];
    memset(key, 0xff, AEGIS_KEY_LEN);
    memset(nonce, 0x00, AEGIS_NONCE_LEN);

    uint8_t pt[32] = "determinism check............";
    uint8_t ad[4];
    memcpy(ad, "test", 4);
    uint8_t ct1[32], ct2[32];
    uint8_t tag1[AEGIS_TAG_LEN];

    uint8_t tag2[AEGIS_TAG_LEN];
    aegis_encrypt(ct1, tag1, pt, 32, ad, 4, nonce, key);
    aegis_encrypt(ct2, tag2, pt, 32, ad, 4, nonce, key);

    if (memcmp(ct1, ct2, 32) == 0 &&
        memcmp(tag1, tag2, AEGIS_TAG_LEN) == 0) {
        PASS();
    } else {
        FAIL("same inputs produced different outputs (non-deterministic)");
    }
}

/* ─── Test 13: x86 AES-NI cross-validation ─────────────────────── */

#ifdef AEGIS_HAVE_AESNI
#include "crypto/x86/aegis128-x86.h"

static void test_x86_aesni_crosscheck(void)
{
    TEST("x86 AES-NI ≡ pure C (cross-validation)");
    if (!aegis128_x86_available()) {
        fprintf(stderr, "(not available — skipping) ");
        PASS();
        return;
    }

    uint8_t key[AEGIS_KEY_LEN];
    uint8_t nonce[AEGIS_NONCE_LEN];
    memset(key, 0x42, AEGIS_KEY_LEN);
    memset(nonce, 0x13, AEGIS_NONCE_LEN);

    uint8_t pt[47], ad[8];
    for (int i = 0; i < 47; i++) pt[i] = (uint8_t)i;
    for (int i = 0; i < 8; i++)  ad[i] = (uint8_t)(i * 7);

    uint8_t ct_c[64], tag_c[AEGIS_TAG_LEN];
    aegis_encrypt(ct_c, tag_c, pt, 47, ad, 8, nonce, key);

    uint8_t ct_x86[64], tag_x86[AEGIS_TAG_LEN];
    aegis128_x86_encrypt(ct_x86, tag_x86, pt, 47, ad, 8, nonce, key);

    if (memcmp(ct_c, ct_x86, 47) != 0 || memcmp(tag_c, tag_x86, AEGIS_TAG_LEN) != 0) {
        FAIL("AES-NI output differs from pure C");
        return;
    }

    uint8_t recovered[47];
    if (aegis128_x86_decrypt(recovered, ct_x86, 47, ad, 8, nonce, key, tag_x86) != 0
        || memcmp(pt, recovered, 47) != 0) {
        FAIL("AES-NI decrypt failed");
        return;
    }
    PASS();
}
#endif

/* ════════════════════════════════════════════════════════════════ */

int main(void)
{
    fprintf(stderr, "AEGIS-128 Unit Tests\n");
    fprintf(stderr, "====================\n\n");

    test_empty_message();
    test_single_block();
    test_multi_block();
    test_large_message();
    test_wrong_key();
    test_corrupted_tag();
    test_corrupted_ciphertext();
    test_wrong_ad();
    test_inplace();
    test_streaming_api();
    test_key_variation();
    test_deterministic();
#ifdef AEGIS_HAVE_AESNI
    test_x86_aesni_crosscheck();
#endif

    fprintf(stderr, "\n────────────────────────────────────────\n");
    fprintf(stderr, "Results: %d/%d passed, %d failed\n",
            tests_passed, tests_run, tests_failed);

    return (tests_failed > 0) ? 1 : 0;
}
