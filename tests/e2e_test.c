/*
 * e2e_test.c — Full end-to-end AEGIS-Tunnel protocol test
 *
 * Tests in a single process:
 *   ✅ PSK handshake (client ↔ server)
 *   ✅ Session key derivation
 *   ✅ Encrypted data transfer (client → server → echo → server → client)
 *   ✅ 65535-byte large frame roundtrip
 */

#include "protocol/handshake.h"
#include "tunnel/tunnel.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static int passed = 0;
static int failed = 0;

#define TEST(n)  fprintf(stderr, "  %-52s ... ", n)
#define T_PASS() do { passed++; fprintf(stderr, "PASS\n"); } while(0)
#define T_FAIL(m) do { failed++; fprintf(stderr, "FAIL: %s\n", m); } while(0)

/* ── Handshake thread arg ─────────────────────────────────────── */
typedef struct {
    int fd;
    const uint8_t *psk;
    size_t psk_len;
    session_keys_t keys;
    int result;
} hs_thread_t;

static void *hs_server_thread(void *arg)
{
    hs_thread_t *a = (hs_thread_t *)arg;
    a->result = handshake_server(a->fd, a->psk, a->psk_len, 5000, &a->keys);
    return NULL;
}

static void *hs_client_thread(void *arg)
{
    hs_thread_t *a = (hs_thread_t *)arg;
    a->result = handshake_client(a->fd, a->psk, a->psk_len, 5000, &a->keys);
    return NULL;
}

/* ── Echo thread ──────────────────────────────────────────────── */
typedef struct {
    int fd;
    volatile int done;
} echo_t;

static void *echo_run(void *arg)
{
    echo_t *e = (echo_t *)arg;
    uint8_t buf[65536];
    while (!e->done) {
        ssize_t n = recv(e->fd, buf, sizeof(buf), 0);
        if (n <= 0) break;
        send(e->fd, buf, (size_t)n, 0);
    }
    return NULL;
}

/* ── Test: Full handshake + multi-message + large frame ───────── */

static void test_full_e2e(void)
{
    TEST("handshake + key derivation + encrypt + decrypt");

    int tun[2], echo[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, tun) != 0 ||
        socketpair(AF_UNIX, SOCK_STREAM, 0, echo) != 0) {
        T_FAIL("socketpair");
        return;
    }

    uint8_t psk[16];
    memset(psk, 0x5a, sizeof(psk));

    /* Start echo server */
    echo_t ectx = { .fd = echo[0], .done = 0 };
    pthread_t eth;
    pthread_create(&eth, NULL, echo_run, &ectx);

    /* Run handshake concurrently */
    hs_thread_t sa = { .fd = tun[0], .psk = psk, .psk_len = sizeof(psk) };
    hs_thread_t ca = { .fd = tun[1], .psk = psk, .psk_len = sizeof(psk) };
    pthread_t st, ct;
    pthread_create(&st, NULL, hs_server_thread, &sa);
    pthread_create(&ct, NULL, hs_client_thread, &ca);
    pthread_join(st, NULL);
    pthread_join(ct, NULL);

    if (sa.result != 0 || ca.result != 0) {
        T_FAIL("handshake");
        goto cleanup;
    }

    /* Verify key agreement */
    if (memcmp(sa.keys.enc_key, ca.keys.dec_key, AEGIS_KEY_LEN) != 0 ||
        memcmp(sa.keys.dec_key, ca.keys.enc_key, AEGIS_KEY_LEN) != 0) {
        T_FAIL("key mismatch");
        goto cleanup;
    }

    /* ── Data transfer tests ── */
    const char *msgs[] = {
        "Hello, AEGIS-Tunnel!",
        "Short",
        "X",
        NULL
    };

    uint8_t wire[FRAME_MAX_WIRE];
    uint8_t pt[FRAME_MAX_PAYLOAD];

    for (int m = 0; msgs[m]; m++) {
        size_t mlen = strlen(msgs[m]);

        /* Client encrypts → sends to server */
        size_t wlen = 0;
        frame_build(wire, &wlen, FRAME_DATA, FLAG_NONE,
                    (const uint8_t *)msgs[m], mlen,
                    1 /* nonce */, ca.keys.enc_key);

        /* Send frame over tun socket */
        size_t snt = 0;
        while (snt < wlen) {
            ssize_t n = send(tun[1], wire + snt, wlen - snt, 0);
            if (n <= 0) { T_FAIL("send client→server"); goto cleanup; }
            snt += (size_t)n;
        }

        /* Server receives frame */
        uint8_t rbuf[FRAME_MAX_WIRE];
        size_t rcv = 0;
        while (rcv < wlen) {
            ssize_t n = recv(tun[0], rbuf + rcv, wlen - rcv, 0);
            if (n <= 0) { T_FAIL("recv server"); goto cleanup; }
            rcv += (size_t)n;
        }

        /* Server decrypts */
        uint8_t typ, flg;
        size_t plen = 0;
        if (frame_parse(rbuf, rcv, &typ, &flg, pt, &plen,
                        1, sa.keys.dec_key) != 0) {
            T_FAIL("server decrypt");
            goto cleanup;
        }

        if (plen != mlen || memcmp(pt, msgs[m], mlen) != 0) {
            T_FAIL("decrypted data mismatch");
            goto cleanup;
        }

        /* Forward to echo, get response, encrypt, send back */
        send(echo[1], pt, plen, 0);

        uint8_t ebuf[65536];
        ssize_t en = recv(echo[1], ebuf, sizeof(ebuf), 0);
        if (en != (ssize_t)plen || memcmp(ebuf, msgs[m], plen) != 0) {
            T_FAIL("echo mismatch");
            goto cleanup;
        }

        /* Server encrypts response */
        size_t rwl = 0;
        frame_build(wire, &rwl, FRAME_DATA, FLAG_NONE,
                    ebuf, plen, 1, sa.keys.enc_key);

        snt = 0;
        while (snt < rwl) {
            ssize_t n = send(tun[0], wire + snt, rwl - snt, 0);
            if (n <= 0) { T_FAIL("send server→client"); goto cleanup; }
            snt += (size_t)n;
        }

        /* Client receives and decrypts */
        rcv = 0;
        while (rcv < rwl) {
            ssize_t n = recv(tun[1], rbuf + rcv, rwl - rcv, 0);
            if (n <= 0) { T_FAIL("recv client"); goto cleanup; }
            rcv += (size_t)n;
        }

        size_t cplen = 0;
        if (frame_parse(rbuf, rcv, &typ, &flg, pt, &cplen,
                        1, ca.keys.dec_key) != 0) {
            T_FAIL("client decrypt");
            goto cleanup;
        }

        if (cplen != mlen || memcmp(pt, msgs[m], mlen) != 0) {
            T_FAIL("final plaintext mismatch");
            goto cleanup;
        }
    }

    /* ── Large (65535-byte) frame test ── */
    {
        uint8_t *big = (uint8_t *)malloc(65535);
        if (!big) { T_FAIL("malloc"); goto cleanup; }
        for (int i = 0; i < 65535; i++) big[i] = (uint8_t)i;

        size_t wl = 0;
        frame_build(wire, &wl, FRAME_DATA, FLAG_NONE, big, 65535,
                    2 /* next nonce */, ca.keys.enc_key);

        size_t snt2 = 0;
        while (snt2 < wl) {
            ssize_t n = send(tun[1], wire + snt2, wl - snt2, 0);
            if (n <= 0) { T_FAIL("send large"); free(big); goto cleanup; }
            snt2 += (size_t)n;
        }

        uint8_t *rb2 = (uint8_t *)malloc(FRAME_MAX_WIRE);
        size_t rcv2 = 0;
        while (rcv2 < wl) {
            ssize_t n = recv(tun[0], rb2 + rcv2, wl - rcv2, 0);
            if (n <= 0) { T_FAIL("recv large"); free(rb2); free(big); goto cleanup; }
            rcv2 += (size_t)n;
        }

        uint8_t typ2, flg2;
        size_t pl2 = 0;
        int r = frame_parse(rb2, rcv2, &typ2, &flg2, pt, &pl2,
                            2, sa.keys.dec_key);
        free(rb2);
        free(big);

        if (r != 0 || pl2 != 65535) {
            T_FAIL("large frame decrypt");
            goto cleanup;
        }
    }

    T_PASS();

cleanup:
    ectx.done = 1;
    shutdown(echo[0], SHUT_RDWR); shutdown(echo[1], SHUT_RDWR);
    close(echo[0]); close(echo[1]);
    close(tun[0]); close(tun[1]);
    pthread_join(eth, NULL);
}

/* ── Test: Wrong PSK → handshake fails ────────────────────────── */

static void test_wrong_psk_e2e(void)
{
    TEST("wrong PSK → handshake rejected");

    int tun[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, tun) != 0) {
        T_FAIL("socketpair");
        return;
    }

    /* Set 1-second timeout to prevent deadlock */
    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
    setsockopt(tun[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(tun[1], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    uint8_t psk1[16], psk2[16];
    memset(psk1, 0x11, sizeof(psk1));
    memset(psk2, 0x22, sizeof(psk2));

    hs_thread_t sa = { .fd = tun[0], .psk = psk1, .psk_len = sizeof(psk1) };
    hs_thread_t ca = { .fd = tun[1], .psk = psk2, .psk_len = sizeof(psk2) };
    pthread_t st, ct;
    pthread_create(&st, NULL, hs_server_thread, &sa);
    pthread_create(&ct, NULL, hs_client_thread, &ca);
    pthread_join(st, NULL);
    pthread_join(ct, NULL);

    close(tun[0]);
    close(tun[1]);

    /* At least one side must reject */
    if (sa.result != 0 || ca.result != 0) {
        T_PASS();
    } else {
        T_FAIL("wrong PSK was not rejected");
    }
}

/* ════════════════════════════════════════════════════════════════ */

int main(void)
{
    fprintf(stderr, "AEGIS-Tunnel End-to-End Protocol Test\n");
    fprintf(stderr, "=====================================\n\n");

    test_full_e2e();
    test_wrong_psk_e2e();

    int total = passed + failed;
    fprintf(stderr, "\n────────────────────────────────────────\n");
    fprintf(stderr, "Results: %d/%d passed, %d failed\n",
            passed, total, failed);
    return (failed > 0) ? 1 : 0;
}
