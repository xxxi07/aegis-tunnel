/*
 * bench_aegis.c — AEGIS-128 throughput benchmark
 *
 * Measures encryption throughput of the pure C implementation.
 * If compiled on ARM with NEON support, also benchmarks the
 * NEON-optimized path.
 */

#include "crypto/aegis.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Benchmark buffer size: 16 MiB */
#define BENCH_BUF_SIZE  (16 * 1024 * 1024)
/* Number of iterations */
#define BENCH_ITERS     50

/* ─── Calculate elapsed time in seconds ───────────────────────── */

static double elapsed_sec(struct timespec *start, struct timespec *end)
{
    double s = (double)(end->tv_sec - start->tv_sec);
    double ns = (double)(end->tv_nsec - start->tv_nsec);
    return s + ns * 1e-9;
}

/* ─── Calculate throughput in MB/s ─────────────────────────────── */

static double calc_mbps(size_t bytes, double sec)
{
    return (double)bytes / (1024.0 * 1024.0) / sec;
}

/* ─── Run pure C benchmark ─────────────────────────────────────── */

static double bench_pure_c(void)
{
    uint8_t key[AEGIS_KEY_LEN] = {0};
    uint8_t nonce[AEGIS_NONCE_LEN] = {0};
    uint8_t *buf = (uint8_t *)malloc(BENCH_BUF_SIZE);
    uint8_t *ct  = (uint8_t *)malloc(BENCH_BUF_SIZE);
    uint8_t tag[AEGIS_TAG_LEN];

    if (!buf || !ct) {
        fprintf(stderr, "malloc failed\n");
        free(buf); free(ct);
        return -1.0;
    }

    /* Fill buffer with non-zero data */
    memset(buf, 0x5a, BENCH_BUF_SIZE);

    struct timespec start, end;

    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < BENCH_ITERS; i++) {
        aegis_encrypt(ct, tag, buf, BENCH_BUF_SIZE, NULL, 0, nonce, key);
        /* Vary nonce to avoid benchmark cheating */
        nonce[0] = (uint8_t)(i & 0xff);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);

    double sec = elapsed_sec(&start, &end);
    double total_bytes = (double)BENCH_BUF_SIZE * BENCH_ITERS;

    free(buf);
    free(ct);

    return calc_mbps((size_t)total_bytes, sec);
}

/* ─── Run NEON benchmark (if available) ────────────────────────── */

/* ─── Run x86 AES-NI benchmark (if available) ──────────────────── */

#ifdef AEGIS_HAVE_AESNI
#include "crypto/x86/aegis128-x86.h"

static double bench_x86_aesni(void)
{
    uint8_t key[AEGIS_KEY_LEN] = {0};
    uint8_t nonce[AEGIS_NONCE_LEN] = {0};
    uint8_t *buf = (uint8_t *)malloc(BENCH_BUF_SIZE);
    uint8_t *ct  = (uint8_t *)malloc(BENCH_BUF_SIZE);

    if (!buf || !ct) { free(buf); free(ct); return -1.0; }
    memset(buf, 0x5a, BENCH_BUF_SIZE);

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < BENCH_ITERS; i++) {
        uint8_t tag[AEGIS_TAG_LEN];
        aegis128_x86_encrypt(ct, tag, buf, BENCH_BUF_SIZE, NULL, 0, nonce, key);
        nonce[0] = (uint8_t)(i & 0xff);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);

    double sec = elapsed_sec(&start, &end);
    double total_bytes = (double)BENCH_BUF_SIZE * BENCH_ITERS;
    free(buf); free(ct);
    return calc_mbps((size_t)total_bytes, sec);
}
#endif

/* ─── Run ARM Crypto benchmark (if available) ─────────────────── */

#ifdef AEGIS_HAVE_ARMCRYPTO
#include "crypto/neon/aegis128-armcrypto.h"

static double bench_armcrypto(void)
{
    uint8_t key[AEGIS_KEY_LEN] = {0};
    uint8_t nonce[AEGIS_NONCE_LEN] = {0};
    uint8_t *buf = (uint8_t *)malloc(BENCH_BUF_SIZE);
    uint8_t *ct  = (uint8_t *)malloc(BENCH_BUF_SIZE);

    if (!buf || !ct) { free(buf); free(ct); return -1.0; }
    memset(buf, 0x5a, BENCH_BUF_SIZE);

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < BENCH_ITERS; i++) {
        uint8_t tag[AEGIS_TAG_LEN];
        aegis128_armcrypto_encrypt(ct, tag, buf, BENCH_BUF_SIZE, NULL, 0, nonce, key);
        nonce[0] = (uint8_t)(i & 0xff);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);

    double sec = elapsed_sec(&start, &end);
    double total_bytes = (double)BENCH_BUF_SIZE * BENCH_ITERS;
    free(buf); free(ct);
    return calc_mbps((size_t)total_bytes, sec);
}
#endif

#ifdef AEGIS_HAVE_NEON
#include "crypto/neon/aegis128-plain.h"

static double bench_neon(void)
{
    uint8_t key[AEGIS_KEY_LEN] = {0};
    uint8_t nonce[AEGIS_NONCE_LEN] = {0};
    uint8_t *buf = (uint8_t *)malloc(BENCH_BUF_SIZE);
    uint8_t *ct  = (uint8_t *)malloc(BENCH_BUF_SIZE);

    if (!buf || !ct) {
        fprintf(stderr, "malloc failed\n");
        free(buf); free(ct);
        return -1.0;
    }

    memset(buf, 0x5a, BENCH_BUF_SIZE);

    aegis128_neon_state_t st;
    struct timespec start, end;

    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < BENCH_ITERS; i++) {
        uint8_t tag[AEGIS_TAG_LEN];
        aegis128_neon_init(&st, key, nonce);

        size_t full = BENCH_BUF_SIZE & ~(size_t)15;
        aegis128_neon_enc_update(&st, ct, buf, full);
        size_t rem = BENCH_BUF_SIZE - full;
        aegis128_neon_enc_final(&st, ct + full, buf + full, rem, tag);

        nonce[0] = (uint8_t)(i & 0xff);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);

    double sec = elapsed_sec(&start, &end);
    double total_bytes = (double)BENCH_BUF_SIZE * BENCH_ITERS;

    free(buf);
    free(ct);

    return calc_mbps((size_t)total_bytes, sec);
}
#endif /* AEGIS_HAVE_NEON */

/* ════════════════════════════════════════════════════════════════ */

int main(void)
{
    printf("AEGIS-128 Throughput Benchmark\n");
    printf("==============================\n");
    printf("Buffer size:  %d MiB\n", BENCH_BUF_SIZE / (1024 * 1024));
    printf("Iterations:   %d\n\n", BENCH_ITERS);

    /* Warm up */
    double warmup = bench_pure_c();
    (void)warmup;

    /* Pure C benchmark */
    double pure_c_mbps = bench_pure_c();
    printf("Pure C:       %8.1f MB/s\n", pure_c_mbps);

    /* x86 AES-NI benchmark (if available) */
#ifdef AEGIS_HAVE_AESNI
    {
        double w = bench_x86_aesni(); (void)w;
        double ni_mbps = bench_x86_aesni();
        printf("x86 AES-NI:   %8.1f MB/s  (%.1fx)\n",
               ni_mbps, ni_mbps / pure_c_mbps);
    }
#else
    printf("x86 AES-NI:   [not available — compile with -maes]\n");
#endif

    /* NEON benchmark (if available) */
#ifdef AEGIS_HAVE_NEON
    {
        double w = bench_neon(); (void)w;
        double neon_mbps = bench_neon();
        printf("NEON (plain): %8.1f MB/s  (%.1fx)\n",
               neon_mbps, neon_mbps / pure_c_mbps);
    }
#else
    printf("NEON (plain): [not available on this platform]\n");
#endif

    /* ARM Crypto benchmark (if available) */
#ifdef AEGIS_HAVE_ARMCRYPTO
    if (aegis128_armcrypto_available()) {
        double w = bench_armcrypto(); (void)w;
        double ac_mbps = bench_armcrypto();
        printf("ARM Crypto:   %8.1f MB/s  (%.1fx)\n",
               ac_mbps, ac_mbps / pure_c_mbps);
    } else
#endif
    printf("ARM Crypto:   [not available on this platform]\n");

    printf("\nPlatform: %s\n",
#ifdef __x86_64__
           "x86_64"
#elif defined(__aarch64__)
           "aarch64 (ARM 64-bit)"
#else
           "unknown"
#endif
    );

    return 0;
}
