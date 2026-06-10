/*
 * e2e_test.c — Full end-to-end protocol test (asymmetric handshake)
 */
#include "protocol/handshake.h"
#include "protocol/ecdh.h"
#include "tunnel/tunnel.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static int passed = 0, failed = 0;
#define T(n)  fprintf(stderr, "  %-52s ... ", n)
#define P()   do { passed++; fprintf(stderr, "PASS\n"); } while(0)
#define F(m)  do { failed++; fprintf(stderr, "FAIL: %s\n", m); } while(0)

typedef struct { int fd; const uint8_t *sk,*pk; session_keys_t k; int r; } hs_t;
static void *hs_srv(void *a_){ hs_t *a=a_; a->r=handshake_server(a->fd,a->sk,a->pk,5000,&a->k); return NULL; }
static void *hs_cli(void *a_){ hs_t *a=a_; a->r=handshake_client(a->fd,a->sk,a->pk,5000,&a->k); return NULL; }

typedef struct { int fd; volatile int done; } echo_t;
static void *echo_run(void *a_){ echo_t *e=a_;uint8_t b[65536];while(!e->done){
    ssize_t n=recv(e->fd,b,sizeof(b),0);if(n<=0)break;send(e->fd,b,(size_t)n,0);}return NULL;}

static int recv_exact(int fd, uint8_t *b, size_t len) {
    size_t r=0; while(r<len){ssize_t n=recv(fd,b+r,len-r,0);if(n<=0)return -1;r+=(size_t)n;}return 0;
}

static void test_full_e2e(void) {
    T("handshake + key derivation + encrypt + decrypt");
    int tun[2],echo[2];
    if(socketpair(AF_UNIX,SOCK_STREAM,0,tun)||socketpair(AF_UNIX,SOCK_STREAM,0,echo)){F("socketpair");return;}

    uint8_t sc[32],pc[32],ss[32],ps[32];ecdh_keygen(pc,sc);ecdh_keygen(ps,ss);

    echo_t e={echo[0],0};pthread_t et;pthread_create(&et,NULL,echo_run,&e);

    hs_t sa={tun[0],ss,pc},ca={tun[1],sc,ps};
    pthread_t st,ct; pthread_create(&st,NULL,hs_srv,&sa); pthread_create(&ct,NULL,hs_cli,&ca);
    pthread_join(st,NULL);pthread_join(ct,NULL);
    if(sa.r||ca.r){F("handshake");goto out;}
    if(memcmp(sa.k.enc_key,ca.k.dec_key,16)||memcmp(sa.k.dec_key,ca.k.enc_key,16)){F("key mismatch");goto out;}

    /* Multi-message test */
    const char *msgs[]={"Hello, AEGIS-Tunnel!","Short","X",NULL};
    uint8_t w[FRAME_MAX_WIRE],pt[FRAME_MAX_PAYLOAD];
    for(int m=0;msgs[m];m++){size_t ml=strlen(msgs[m]);size_t wl=0;
        frame_build(w,&wl,FRAME_DATA,FLAG_NONE,(const uint8_t*)msgs[m],ml,1,ca.k.enc_key);
        send(tun[1],w,wl,0);
        uint8_t rb[FRAME_MAX_WIRE];size_t h_expected=FRAME_HEADER_LEN;
        if(recv_exact(tun[0],rb,h_expected)){F("server hdr");goto out;}
        uint16_t plen=(uint16_t)((rb[2]<<8)|rb[3]);size_t expected=plen+AEGIS_TAG_LEN;
        if(recv_exact(tun[0],rb+h_expected,expected)){F("server ct");goto out;}
        uint8_t ty,fl;size_t pl=0;
        if(frame_parse(rb,h_expected+expected,&ty,&fl,pt,&pl,1,sa.k.dec_key)){F("decrypt");goto out;}
        if(send(echo[1],pt,pl,0)!=(ssize_t)pl){F("echo send");goto out;}
        uint8_t eb[65536];
        if(recv_exact(echo[1],eb,pl)){F("echo recv");goto out;}
        if(memcmp(eb,msgs[m],pl)){F("echo mismatch");goto out;}
        size_t rwl;frame_build(w,&rwl,FRAME_DATA,FLAG_NONE,eb,pl,1,sa.k.enc_key);
        send(tun[0],w,rwl,0);
        h_expected=FRAME_HEADER_LEN;
        if(recv_exact(tun[1],rb,h_expected)){F("client hdr");goto out;}
        plen=(uint16_t)((rb[2]<<8)|rb[3]);expected=plen+AEGIS_TAG_LEN;
        if(recv_exact(tun[1],rb+h_expected,expected)){F("client ct");goto out;}
        size_t cpl;uint8_t ty2,fl2;
        if(frame_parse(rb,h_expected+expected,&ty2,&fl2,pt,&cpl,1,ca.k.dec_key)||cpl!=ml||memcmp(pt,msgs[m],ml)){F("final mismatch");goto out;}}

    /* 65535 byte test */
    {uint8_t *big=(uint8_t*)malloc(65535);if(!big){F("malloc");goto out;}
     for(int i=0;i<65535;i++)big[i]=(uint8_t)i;
     size_t wl;frame_build(w,&wl,FRAME_DATA,FLAG_NONE,big,65535,2,ca.k.enc_key);
     send(tun[1],w,wl,0);
     size_t h_exp=FRAME_HEADER_LEN;
     if(recv_exact(tun[0],w,h_exp)){F("large hdr");free(big);goto out;}
     uint16_t plen2=(uint16_t)((w[2]<<8)|w[3]);size_t exp2=plen2+AEGIS_TAG_LEN;
     if(recv_exact(tun[0],w+h_exp,exp2)){F("large ct");free(big);goto out;}
     uint8_t ty3,fl3;size_t pl3;
     frame_parse(w,h_exp+exp2,&ty3,&fl3,pt,&pl3,2,sa.k.dec_key);
     free(big);if(pl3!=65535){F("large mismatch");goto out;}}

    P();
out:e.done=1;shutdown(echo[0],SHUT_RDWR);shutdown(echo[1],SHUT_RDWR);
    close(echo[0]);close(echo[1]);close(tun[0]);close(tun[1]);pthread_join(et,NULL);
}

static void test_wrong_peer(void) {
    T("wrong peer pubkey → handshake rejected");
    int fds[2];socketpair(AF_UNIX,SOCK_STREAM,0,fds);
    struct timeval tv={.tv_sec=1};setsockopt(fds[0],SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));setsockopt(fds[1],SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));
    uint8_t sc[32],pc[32],ss[32],ps[32],wp[32];ecdh_keygen(pc,sc);ecdh_keygen(ps,ss);memset(wp,0xff,32);
    hs_t sa={fds[0],ss,pc},ca={fds[1],sc,wp};
    pthread_t st,ct;pthread_create(&st,NULL,hs_srv,&sa);pthread_create(&ct,NULL,hs_cli,&ca);
    pthread_join(st,NULL);pthread_join(ct,NULL);
    if(sa.r||ca.r) P(); else F("should reject");
    close(fds[0]);close(fds[1]);
}

int main(void){fprintf(stderr,"AEGIS-Tunnel End-to-End Test\n=============================\n\n");
    test_full_e2e();test_wrong_peer();
    fprintf(stderr,"\nResults: %d/%d passed, %d failed\n",passed,passed+failed,failed);
    return failed?1:0;}
