/*
 * test_asymmetric.c — Asymmetric handshake test (WireGuard model)
 *
 * Validates the 3-DH handshake without shared PSK.
 */
#include "protocol/handshake.h"
#include "protocol/ecdh.h"
#include "protocol/keyfile.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <pthread.h>

static int passed = 0, failed = 0;
#define T(n)  fprintf(stderr, "  %-52s ... ", n)
#define P()   do { passed++; fprintf(stderr, "PASS\n"); } while(0)
#define F(m)  do { failed++; fprintf(stderr, "FAIL: %s\n", m); } while(0)

typedef struct {
    int fd;
    const uint8_t *our_priv;
    const uint8_t *peer_pub;
    session_keys_t keys;
    int result;
} asym_thread_t;

static void *asym_server_thread(void *arg)
{
    asym_thread_t *a = (asym_thread_t *)arg;
    a->result = handshake_asymmetric_server(a->fd, a->our_priv, a->peer_pub, 5000, &a->keys);
    return NULL;
}

static void test_asymmetric_handshake(void)
{
    T("asymmetric handshake (no PSK, 3-DH)");

    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) { F("socketpair"); return; }

    /* Generate keypairs for both sides */
    uint8_t sk_c[32], pk_c[32], sk_s[32], pk_s[32];
    ecdh_keygen(pk_c, sk_c);
    ecdh_keygen(pk_s, sk_s);

    /* Set timeouts */
    struct timeval tv = { .tv_sec = 3, .tv_usec = 0 };
    setsockopt(fds[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fds[1], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* Start server thread */
    asym_thread_t sa = { .fd = fds[0], .our_priv = sk_s, .peer_pub = pk_c };
    pthread_t st;
    pthread_create(&st, NULL, asym_server_thread, &sa);

    /* Client initiates */
    session_keys_t ck;
    int cr = handshake_asymmetric_client(fds[1], sk_c, pk_s, 5000, &ck);
    pthread_join(st, NULL);

    if (cr != 0 || sa.result != 0) { F("handshake"); goto out; }

    /* Verify key agreement */
    if (memcmp(ck.enc_key, sa.keys.dec_key, AEGIS_KEY_LEN) != 0 ||
        memcmp(ck.dec_key, sa.keys.enc_key, AEGIS_KEY_LEN) != 0) {
        F("key mismatch"); goto out;
    }

    /* Key confirmation */
    if (handshake_key_confirm_server(fds[0], &sa.keys, 5000) != 0 ||
        handshake_key_confirm_client(fds[1], &ck, 5000) != 0) {
        F("key confirm"); goto out;
    }

    P();
out:
    close(fds[0]); close(fds[1]);
}

static void test_asymmetric_wrong_keys(void)
{
    T("asymmetric: wrong peer pubkey → rejected");

    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) { F("socketpair"); return; }

    struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
    setsockopt(fds[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fds[1], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* Server has correct keypair, client has wrong peer_pub */
    uint8_t sk_s[32], pk_s[32], sk_c[32], pk_c[32], wrong_pub[32];
    ecdh_keygen(pk_s, sk_s);
    ecdh_keygen(pk_c, sk_c);
    ecdh_keygen(wrong_pub, sk_c); /* just to get a random pubkey */
    (void)wrong_pub;
    /* Actually use a genuinely different pubkey */
    memset(wrong_pub, 0xff, 32);

    asym_thread_t sa = { .fd = fds[0], .our_priv = sk_s, .peer_pub = pk_c };
    pthread_t st;
    pthread_create(&st, NULL, asym_server_thread, &sa);

    session_keys_t ck;
    int cr = handshake_asymmetric_client(fds[1], sk_c, wrong_pub, 5000, &ck);
    pthread_join(st, NULL);

    if (cr != 0 || sa.result != 0) P(); else F("should have rejected");

    close(fds[0]); close(fds[1]);
}

int main(void)
{
    fprintf(stderr, "AEGIS-Tunnel Asymmetric Handshake Test\n");
    fprintf(stderr, "=======================================\n\n");

    test_asymmetric_handshake();
    test_asymmetric_wrong_keys();

    int total = passed + failed;
    fprintf(stderr, "\nResults: %d/%d passed, %d failed\n", passed, total, failed);
    return (failed > 0) ? 1 : 0;
}
