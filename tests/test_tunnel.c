/*
 * test_tunnel.c — Frame protocol integration tests (asymmetric handshake)
 */
#include "protocol/handshake.h"
#include "protocol/ecdh.h"
#include "tunnel/tunnel.h"
#include "util/util.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static int passed = 0, failed = 0;
#define T(n)  fprintf(stderr, "  %-50s ... ", n)
#define P()   do { passed++; fprintf(stderr, "PASS\n"); } while(0)
#define F(m)  do { failed++; fprintf(stderr, "FAIL: %s\n", m); } while(0)

static int make_pair(int fds[2]) { return socketpair(AF_UNIX, SOCK_STREAM, 0, fds); }

/* ─── Test 1: frame roundtrip ─────────────────────────────────── */
static void test_frame_roundtrip(void) {
    T("frame build → parse roundtrip (DATA, 100 bytes)");
    uint8_t key[AEGIS_KEY_LEN]; memset(key, 0x42, AEGIS_KEY_LEN);
    uint8_t payload[100]; for (int i=0;i<100;i++) payload[i]=(uint8_t)(i*3);
    uint8_t wire[FRAME_MAX_WIRE]; size_t wl=0;
    if (frame_build(wire,&wl,FRAME_DATA,FLAG_NONE,payload,100,1,key)!=0) { F("build"); return; }
    uint8_t ty,fl,rec[FRAME_MAX_PAYLOAD]; size_t rl=0;
    if (frame_parse(wire,wl,&ty,&fl,rec,&rl,1,key)!=0) { F("parse"); return; }
    if (ty!=FRAME_DATA||rl!=100||memcmp(payload,rec,100)!=0) { F("mismatch"); return; }
    P();
}

/* ─── Test 2: wrong nonce ────────────────────────────────────── */
static void test_frame_wrong_nonce(void) {
    T("frame parse rejects wrong nonce counter");
    uint8_t key[AEGIS_KEY_LEN]; memset(key,0x42,AEGIS_KEY_LEN);
    uint8_t pl[16]; memcpy(pl,"test payload!...",16);
    uint8_t wire[FRAME_MAX_WIRE]; size_t wl=0;
    frame_build(wire,&wl,FRAME_DATA,FLAG_NONE,pl,16,5,key);
    uint8_t ty,fl,rec[FRAME_MAX_PAYLOAD]; size_t rl=0;
    if (frame_parse(wire,wl,&ty,&fl,rec,&rl,3,key)!=0) P(); else F("should reject");
}

/* ─── Test 3: KEEPALIVE ──────────────────────────────────────── */
static void test_frame_keepalive(void) {
    T("frame build → parse KEEPALIVE (zero payload)");
    uint8_t key[AEGIS_KEY_LEN]; memset(key,0x77,AEGIS_KEY_LEN);
    uint8_t wire[FRAME_MAX_WIRE]; size_t wl=0;
    frame_build(wire,&wl,FRAME_KEEPALIVE,FLAG_NONE,NULL,0,10,key);
    uint8_t ty,fl,rec[FRAME_MAX_PAYLOAD]; size_t rl=0;
    if (frame_parse(wire,wl,&ty,&fl,rec,&rl,10,key)!=0||ty!=FRAME_KEEPALIVE||rl!=0) { F("keepalive"); return; }
    P();
}

/* ─── Test 4: Handshake + data transfer ──────────────────────── */
typedef struct { int fd; const uint8_t *sk; const uint8_t *pk; session_keys_t k; int r; } hs_ctx_t;
static void *hs_srv(void *a_) {
    hs_ctx_t *a=(hs_ctx_t*)a_;
    a->r=handshake_server(a->fd,a->sk,a->pk,5000,&a->k);
    if(a->r==0){tunnel_t t;tunnel_init(&t,a->fd,a->fd,a->k.enc_key,a->k.dec_key);
        tunnel_send_data(&t,(const uint8_t*)"Hello from server!",19);}
    return NULL;
}
static void test_end_to_end(void) {
    T("handshake + data transfer (end-to-end)");
    int fds[2]; if(make_pair(fds)!=0){F("socketpair");return;}
    uint8_t sc[32],pc[32],ss[32],ps[32];ecdh_keygen(pc,sc);ecdh_keygen(ps,ss);
    struct timeval tv={.tv_sec=3};setsockopt(fds[0],SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));setsockopt(fds[1],SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));
    hs_ctx_t a={fds[0],ss,pc,{{0}},0};
    pthread_t t;pthread_create(&t,NULL,hs_srv,&a);
    session_keys_t ck; int cr=handshake_client(fds[1],sc,ps,5000,&ck);
    pthread_join(t,NULL);
    if(cr!=0||a.r!=0){F("handshake");goto out;}
    if(memcmp(ck.enc_key,a.k.dec_key,16)!=0||memcmp(ck.dec_key,a.k.enc_key,16)!=0){F("key mismatch");goto out;}
    uint8_t hdr[4]; recv(fds[1],hdr,4,0);
    uint16_t plen=(uint16_t)((hdr[2]<<8)|hdr[3]);
    uint8_t *rb=(uint8_t*)malloc(plen+AEGIS_TAG_LEN); recv(fds[1],rb,plen+AEGIS_TAG_LEN,0);
    uint8_t fb[FRAME_MAX_WIRE]; memcpy(fb,hdr,4);memcpy(fb+4,rb,plen+AEGIS_TAG_LEN);free(rb);
    uint8_t ty,fl,rec[64]; size_t rl=0;
    if(frame_parse(fb,4+plen+AEGIS_TAG_LEN,&ty,&fl,rec,&rl,1,ck.dec_key)!=0||rl!=19||memcmp(rec,"Hello from server!",19)!=0){F("data");goto out;}
    P();
out: close(fds[0]);close(fds[1]);
}

/* ─── Test 5: Wrong peer pubkey rejected ─────────────────────── */
static void test_wrong_peer(void) {
    T("wrong peer pubkey → handshake rejected");
    int fds[2]; if(make_pair(fds)!=0){F("socketpair");return;}
    uint8_t sc[32],pc[32],ss[32],ps[32],wp[32];
    ecdh_keygen(pc,sc);ecdh_keygen(ps,ss);memset(wp,0xff,32);
    struct timeval tv={.tv_sec=2};setsockopt(fds[0],SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));setsockopt(fds[1],SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));
    hs_ctx_t a={fds[0],ss,pc,{{0}},0};
    pthread_t t;pthread_create(&t,NULL,hs_srv,&a);
    session_keys_t ck; int cr=handshake_client(fds[1],sc,wp,5000,&ck);
    pthread_join(t,NULL);
    if(cr!=0||a.r!=0) P(); else F("should reject");
    close(fds[0]);close(fds[1]);
}

/* ─── Test 6: Large frame ────────────────────────────────────── */
static void test_large_frame(void) {
    T("large frame (65535 bytes) roundtrip");
    uint8_t key[AEGIS_KEY_LEN];memset(key,0x99,AEGIS_KEY_LEN);
    uint8_t *pl=(uint8_t*)malloc(FRAME_MAX_PAYLOAD);if(!pl){F("malloc");return;}
    for(int i=0;i<FRAME_MAX_PAYLOAD;i++)pl[i]=(uint8_t)i;
    uint8_t *wb=(uint8_t*)malloc(FRAME_MAX_WIRE);size_t wl=0;
    frame_build(wb,&wl,FRAME_DATA,FLAG_NONE,pl,FRAME_MAX_PAYLOAD,1,key);
    uint8_t ty,fl,*rec=(uint8_t*)malloc(FRAME_MAX_PAYLOAD);size_t rl=0;
    if(frame_parse(wb,wl,&ty,&fl,rec,&rl,1,key)!=0||rl!=FRAME_MAX_PAYLOAD||memcmp(pl,rec,FRAME_MAX_PAYLOAD)!=0){F("mismatch");free(pl);free(wb);free(rec);return;}
    free(pl);free(wb);free(rec);P();
}

/* ─── Test 7: Corrupted tag ──────────────────────────────────── */
static void test_frame_tag_corruption(void) {
    T("corrupted frame tag → rejected");
    uint8_t key[AEGIS_KEY_LEN];memset(key,0xab,AEGIS_KEY_LEN);
    uint8_t pl[32];memset(pl,0x5a,32);
    uint8_t wire[FRAME_MAX_WIRE];size_t wl=0;
    frame_build(wire,&wl,FRAME_DATA,FLAG_NONE,pl,32,42,key);
    wire[wl-1]^=0x01;
    uint8_t ty,fl,rec[FRAME_MAX_PAYLOAD];size_t rl=0;
    if(frame_parse(wire,wl,&ty,&fl,rec,&rl,42,key)!=0) P(); else F("should reject");
}

int main(void) {
    fprintf(stderr,"AEGIS-Tunnel Integration Tests\n==============================\n\n");
    test_frame_roundtrip(); test_frame_wrong_nonce(); test_frame_keepalive();
    test_end_to_end(); test_wrong_peer(); test_large_frame(); test_frame_tag_corruption();
    fprintf(stderr,"\nResults: %d/%d passed, %d failed\n",passed,passed+failed,failed);
    return (failed>0)?1:0;
}
