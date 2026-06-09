/*
 * test_tunnel.c — End-to-end tunnel integration tests
 *
 * Tests the complete tunnel stack: handshake + frame protocol.
 * Uses a pair of connected sockets to simulate client/server
 * communication within a single process.
 */

#include "protocol/handshake.h"
#include "tunnel/tunnel.h"
#include "util/util.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) do { \
    tests_run++; \
    fprintf(stderr, "  %-50s ... ", name); \
} while(0)

#define PASS() do { \
    tests_passed++; \
    fprintf(stderr, "PASS\n"); \
} while(0)

#define FAIL(msg) do { \
    tests_failed++; \
    fprintf(stderr, "FAIL: %s\n", msg); \
} while(0)

/* ─── Helper: create a connected socket pair ───────────────────── */
/*
 * Creates two connected TCP sockets via socketpair() equivalent.
 * Returns 0 on success, sets fds[0] and fds[1].
 */
static int make_socketpair(int fds[2])
{
    /* Use socketpair for a connected pair of Unix-domain sockets */
    return socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
}

/* ─── Test 1: Frame build then parse roundtrip ─────────────────── */

static void test_frame_roundtrip(void)
{
    TEST("frame build → parse roundtrip (DATA, 100 bytes)");
    uint8_t key[AEGIS_KEY_LEN];
    memset(key, 0x42, AEGIS_KEY_LEN);

    uint8_t payload[100];
    for (int i = 0; i < 100; i++) payload[i] = (uint8_t)(i * 3);

    uint8_t wire_buf[FRAME_MAX_WIRE];
    size_t wire_len = 0;

    int ret = frame_build(wire_buf, &wire_len,
                          FRAME_DATA, FLAG_NONE,
                          payload, 100,
                          1, /* nonce counter */
                          key);
    if (ret != 0) {
        FAIL("frame_build failed");
        return;
    }

    /* Verify wire length */
    if (wire_len != FRAME_HEADER_LEN + 100 + AEGIS_TAG_LEN) {
        FAIL("wrong wire length");
        return;
    }

    /* Parse it back */
    uint8_t type, flags;
    uint8_t recovered[FRAME_MAX_PAYLOAD];
    size_t recovered_len = 0;

    ret = frame_parse(wire_buf, wire_len,
                      &type, &flags,
                      recovered, &recovered_len,
                      1, key);
    if (ret != 0) {
        FAIL("frame_parse rejected valid frame");
        return;
    }

    if (type != FRAME_DATA) {
        FAIL("wrong frame type");
        return;
    }

    if (recovered_len != 100) {
        FAIL("wrong payload length");
        return;
    }

    if (memcmp(payload, recovered, 100) != 0) {
        FAIL("payload mismatch");
        return;
    }

    PASS();
}

/* ─── Test 2: Frame tag verification with wrong nonce ──────────── */

static void test_frame_wrong_nonce(void)
{
    TEST("frame parse rejects wrong nonce counter");
    uint8_t key[AEGIS_KEY_LEN];
    memset(key, 0x42, AEGIS_KEY_LEN);

    uint8_t payload[16];
    memcpy(payload, "test payload!...", 16);
    uint8_t wire_buf[FRAME_MAX_WIRE];
    size_t wire_len = 0;

    frame_build(wire_buf, &wire_len,
                FRAME_DATA, FLAG_NONE,
                payload, 16,
                5, /* nonce = 5 */
                key);

    /* Try to parse with wrong nonce (3 instead of 5) */
    uint8_t type, flags;
    uint8_t recovered[FRAME_MAX_PAYLOAD];
    size_t recovered_len = 0;

    int ret = frame_parse(wire_buf, wire_len,
                          &type, &flags,
                          recovered, &recovered_len,
                          3, /* wrong nonce! */
                          key);
    if (ret != 0) {
        PASS();
    } else {
        FAIL("wrong nonce should have caused authentication failure");
    }
}

/* ─── Test 3: Frame build with KEEPALIVE ───────────────────────── */

static void test_frame_keepalive(void)
{
    TEST("frame build → parse KEEPALIVE (zero payload)");
    uint8_t key[AEGIS_KEY_LEN];
    memset(key, 0x77, AEGIS_KEY_LEN);

    uint8_t wire_buf[FRAME_MAX_WIRE];
    size_t wire_len = 0;

    int ret = frame_build(wire_buf, &wire_len,
                          FRAME_KEEPALIVE, FLAG_NONE,
                          NULL, 0,
                          10, key);
    if (ret != 0) {
        FAIL("frame_build KEEPALIVE failed");
        return;
    }

    if (wire_len != FRAME_HEADER_LEN + 0 + AEGIS_TAG_LEN) {
        FAIL("wrong KEEPALIVE wire length");
        return;
    }

    uint8_t type, flags;
    uint8_t recovered[FRAME_MAX_PAYLOAD];
    size_t recovered_len = 0;

    ret = frame_parse(wire_buf, wire_len,
                      &type, &flags,
                      recovered, &recovered_len,
                      10, key);
    if (ret != 0) {
        FAIL("frame_parse rejected valid KEEPALIVE");
        return;
    }

    if (type != FRAME_KEEPALIVE || recovered_len != 0) {
        FAIL("wrong KEEPALIVE type or length");
        return;
    }

    PASS();
}

/* ─── Test 4: Handshake + data transfer (end-to-end) ───────────── */

typedef struct {
    int fd;
    const uint8_t *psk;
    size_t psk_len;
    int *result;
} handshake_thread_arg_t;

static void *server_thread_func(void *arg)
{
    handshake_thread_arg_t *a = (handshake_thread_arg_t *)arg;
    session_keys_t keys;

    int ret = handshake_server(a->fd, a->psk, a->psk_len, 5000, &keys);
    if (ret != 0) {
        *(a->result) = -1;
        return NULL;
    }

    /* After handshake, send a DATA frame */
    const char *msg = "Hello from server!";
    tunnel_t tun;
    /* Use fd as both client_fd and remote_fd for testing */
    tunnel_init(&tun, a->fd, a->fd, keys.enc_key, keys.dec_key);

    ret = tunnel_send_data(&tun, (const uint8_t *)msg, strlen(msg));
    *(a->result) = (ret > 0) ? 0 : -1;
    return NULL;
}

static void test_end_to_end(void)
{
    TEST("handshake + data transfer (end-to-end)");
    int fds[2];
    if (make_socketpair(fds) != 0) {
        FAIL("socketpair failed");
        return;
    }

    /* PSK */
    uint8_t psk[16];
    memset(psk, 0x5a, sizeof(psk));

    /* Start server thread */
    int server_result = -2;
    handshake_thread_arg_t arg = { fds[0], psk, sizeof(psk), &server_result };
    pthread_t server_thread;
    pthread_create(&server_thread, NULL, server_thread_func, &arg);

    /* Client side: handshake */
    session_keys_t keys;
    int ret = handshake_client(fds[1], psk, sizeof(psk), 5000, &keys);
    if (ret != 0) {
        FAIL("client handshake failed");
        close(fds[0]);
        close(fds[1]);
        pthread_join(server_thread, NULL);
        return;
    }

    /* Wait for server thread to complete */
    pthread_join(server_thread, NULL);

    if (server_result != 0) {
        FAIL("server handshake or data send failed");
        close(fds[0]);
        close(fds[1]);
        return;
    }

    /* Receive the DATA frame from server */
    tunnel_t tun;
    tunnel_init(&tun, fds[1], fds[1], keys.enc_key, keys.dec_key);

    /* Read the frame header directly */
    uint8_t header[FRAME_HEADER_LEN];
    ssize_t n = recv(fds[1], header, FRAME_HEADER_LEN, 0);
    if (n != FRAME_HEADER_LEN) {
        FAIL("failed to read frame header");
        close(fds[0]);
        close(fds[1]);
        return;
    }

    size_t payload_len = (size_t)(((uint16_t)header[2] << 8) | header[3]);
    uint8_t *ct_buf = (uint8_t *)malloc(payload_len + AEGIS_TAG_LEN);
    if (!ct_buf) {
        FAIL("malloc failed");
        close(fds[0]);
        close(fds[1]);
        return;
    }

    n = recv(fds[1], ct_buf, payload_len + AEGIS_TAG_LEN, 0);
    if (n != (ssize_t)(payload_len + AEGIS_TAG_LEN)) {
        FAIL("failed to read ciphertext + tag");
        free(ct_buf);
        close(fds[0]);
        close(fds[1]);
        return;
    }

    /* Parse the frame */
    uint8_t type, flags;
    uint8_t plaintext[FRAME_MAX_PAYLOAD];
    size_t plaintext_len = 0;

    size_t wire_len = FRAME_HEADER_LEN + payload_len + AEGIS_TAG_LEN;
    uint8_t *wire_buf = (uint8_t *)malloc(wire_len);
    memcpy(wire_buf, header, FRAME_HEADER_LEN);
    memcpy(wire_buf + FRAME_HEADER_LEN, ct_buf, payload_len + AEGIS_TAG_LEN);
    free(ct_buf);

    ret = frame_parse(wire_buf, wire_len,
                      &type, &flags,
                      plaintext, &plaintext_len,
                      1, /* first data nonce */
                      keys.dec_key);
    free(wire_buf);

    if (ret != 0) {
        FAIL("frame parse failed on received data");
        close(fds[0]);
        close(fds[1]);
        return;
    }

    const char *expected = "Hello from server!";
    if (plaintext_len != strlen(expected) ||
        memcmp(plaintext, expected, plaintext_len) != 0) {
        FAIL("received wrong message");
        close(fds[0]);
        close(fds[1]);
        return;
    }

    close(fds[0]);
    close(fds[1]);
    PASS();
}

/* ─── Test 5: Wrong PSK rejection ──────────────────────────────── */

static void *wrong_psk_server_func(void *arg)
{
    handshake_thread_arg_t *a = (handshake_thread_arg_t *)arg;
    session_keys_t keys;
    int ret = handshake_server(a->fd, a->psk, a->psk_len, 5000, &keys);
    *(a->result) = ret;
    return NULL;
}

static void test_wrong_psk_rejection(void)
{
    TEST("wrong PSK → handshake rejected");
    int fds[2];
    if (make_socketpair(fds) != 0) {
        FAIL("socketpair failed");
        return;
    }

    uint8_t correct_psk[16];
    uint8_t wrong_psk[16];
    memset(correct_psk, 0x11, sizeof(correct_psk));
    memset(wrong_psk, 0x22, sizeof(wrong_psk));

    /* Set 1-second timeout on both sockets to prevent deadlock */
    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
    setsockopt(fds[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fds[1], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* Server uses correct PSK */
    int server_result = -2;
    handshake_thread_arg_t arg = { fds[0], correct_psk, sizeof(correct_psk), &server_result };
    pthread_t server_thread;
    pthread_create(&server_thread, NULL, wrong_psk_server_func, &arg);

    /* Client uses wrong PSK — may fail sending or receiving */
    session_keys_t keys;
    int client_ret = handshake_client(fds[1], wrong_psk, sizeof(wrong_psk), 5000, &keys);

    pthread_join(server_thread, NULL);

    /* At least one side should detect the mismatch */
    if (client_ret != 0 || server_result != 0) {
        PASS();
    } else {
        FAIL("wrong PSK should have been rejected");
    }

    close(fds[0]);
    close(fds[1]);
}

/* ─── Test 6: Large frame (65535 bytes) ────────────────────────── */

static void test_large_frame(void)
{
    TEST("large frame (65535 bytes) roundtrip");
    uint8_t key[AEGIS_KEY_LEN];
    memset(key, 0x99, AEGIS_KEY_LEN);

    uint8_t *payload = (uint8_t *)malloc(FRAME_MAX_PAYLOAD);
    if (!payload) {
        FAIL("malloc failed");
        return;
    }

    for (int i = 0; i < FRAME_MAX_PAYLOAD; i++) {
        payload[i] = (uint8_t)(i & 0xff);
    }

    uint8_t *wire_buf = (uint8_t *)malloc(FRAME_MAX_WIRE);
    if (!wire_buf) {
        FAIL("malloc failed");
        free(payload);
        return;
    }

    size_t wire_len = 0;
    int ret = frame_build(wire_buf, &wire_len,
                          FRAME_DATA, FLAG_NONE,
                          payload, FRAME_MAX_PAYLOAD,
                          1, key);
    if (ret != 0) {
        FAIL("frame_build failed for large frame");
        free(payload);
        free(wire_buf);
        return;
    }

    uint8_t type, flags;
    uint8_t *recovered = (uint8_t *)malloc(FRAME_MAX_PAYLOAD);
    size_t recovered_len = 0;

    ret = frame_parse(wire_buf, wire_len,
                      &type, &flags,
                      recovered, &recovered_len,
                      1, key);
    if (ret != 0) {
        FAIL("frame_parse failed for large frame");
        free(payload);
        free(wire_buf);
        free(recovered);
        return;
    }

    if (recovered_len != FRAME_MAX_PAYLOAD ||
        memcmp(payload, recovered, FRAME_MAX_PAYLOAD) != 0) {
        FAIL("large frame payload mismatch");
        free(payload);
        free(wire_buf);
        free(recovered);
        return;
    }

    free(payload);
    free(wire_buf);
    free(recovered);
    PASS();
}

/* ─── Test 7: Corrupted frame tag ──────────────────────────────── */

static void test_frame_tag_corruption(void)
{
    TEST("corrupted frame tag → rejected");
    uint8_t key[AEGIS_KEY_LEN];
    memset(key, 0xab, AEGIS_KEY_LEN);

    uint8_t payload[32] = "tag corruption test payload...";
    uint8_t wire_buf[FRAME_MAX_WIRE];
    size_t wire_len = 0;

    frame_build(wire_buf, &wire_len,
                FRAME_DATA, FLAG_NONE,
                payload, 32,
                42, key);

    /* Flip a bit in the tag (last 16 bytes) */
    wire_buf[wire_len - 1] ^= 0x01;

    uint8_t type, flags;
    uint8_t recovered[FRAME_MAX_PAYLOAD];
    size_t recovered_len = 0;

    int ret = frame_parse(wire_buf, wire_len,
                          &type, &flags,
                          recovered, &recovered_len,
                          42, key);
    if (ret != 0) {
        PASS();
    } else {
        FAIL("corrupted tag should have been rejected");
    }
}

/* ════════════════════════════════════════════════════════════════ */

int main(void)
{
    fprintf(stderr, "AEGIS-Tunnel Integration Tests\n");
    fprintf(stderr, "==============================\n\n");

    test_frame_roundtrip();
    test_frame_wrong_nonce();
    test_frame_keepalive();
    test_end_to_end();
    test_wrong_psk_rejection();
    test_large_frame();
    test_frame_tag_corruption();

    fprintf(stderr, "\n────────────────────────────────────────\n");
    fprintf(stderr, "Results: %d/%d passed, %d failed\n",
            tests_passed, tests_run, tests_failed);

    return (tests_failed > 0) ? 1 : 0;
}
