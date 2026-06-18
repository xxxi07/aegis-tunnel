/*
 * handshake.c — Asymmetric 3-DH X25519 handshake + key confirm + rekey
 */
#include "protocol/ecdh.h"
#include "protocol/handshake.h"
#include "tunnel/tunnel.h"
#include "util/util.h"
#include <errno.h>
#include <openssl/evp.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define TIMESTAMP_WINDOW_SEC  60

static void sha256_h(uint8_t out[32], const uint8_t *in, size_t len) {
    EVP_MD_CTX *c = EVP_MD_CTX_new(); unsigned int o = 0;
    EVP_DigestInit_ex(c, EVP_sha256(), NULL);
    EVP_DigestUpdate(c, in, len);
    EVP_DigestFinal_ex(c, out, &o);
    EVP_MD_CTX_free(c);
}
static int check_ts(int64_t ts) { int64_t n=timestamp_now(); if(n<0)return -1; int64_t d=(n>ts)?(n-ts):(ts-n); return d>60?-1:0; }
int send_all(int fd, const uint8_t *b, size_t n) { size_t s=0; while(s<n){ ssize_t r=send(fd,b+s,n-s,0); if(r<0){if(errno==EINTR)continue;return -1;} if(r==0)return -1; s+=(size_t)r;} return 0; }

#include <poll.h>
int recv_all(int fd, uint8_t *b, size_t n) {
    size_t r = 0;
    while (r < n) {
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        int pret = poll(&pfd, 1, 500);  /* 500ms per chunk */
        if (pret < 0) { if (errno == EINTR) continue; fprintf(stderr,"[handshake] poll error: %s\n",strerror(errno)); return -1; }
        if (pret == 0) { fprintf(stderr,"[handshake] poll timeout (got %zu/%zu)\n",r,n); return -1; }
        if (pfd.revents & (POLLERR|POLLHUP|POLLNVAL)) { fprintf(stderr,"[handshake] socket error/hangup (got %zu/%zu)\n",r,n); return -1; }
        ssize_t x = recv(fd, b + r, n - r, 0);
        if (x < 0) { if (errno == EINTR) continue; fprintf(stderr,"[handshake] recv error: %s (got %zu/%zu)\n",strerror(errno),r,n); return -1; }
        if (x == 0) { fprintf(stderr,"[handshake] recv EOF after %zu/%zu bytes\n",r,n); return -1; }
        r += (size_t)x;
    }
    return 0;
}

/* ═══════════════════════════════════════════════════ asymmetric handshake */

#define ALEN 36
#define WLEN 60

static int asym_send(int fd, const uint8_t epk[32], int64_t ts, const uint8_t key[16]) {
    uint8_t w[WLEN], ad[ALEN]; w[0]=FRAME_HANDSHAKE;w[1]=FLAG_NONE;w[2]=0;w[3]=8; memcpy(w+4,epk,32);
    memcpy(ad,w,4);memcpy(ad+4,epk,32); uint8_t tsb[8];uint64_t tb=(uint64_t)ts;
    for(int i=0;i<8;i++)tsb[7-i]=(uint8_t)(tb>>(i*8));
    uint8_t n[16]={0}; aegis_encrypt(w+36,w+44,tsb,8,ad,ALEN,n,key); return send_all(fd,w,WLEN);
}
static int asym_hdr(int fd, uint8_t epk[32]) { uint8_t w[ALEN]; if(recv_all(fd,w,ALEN)!=0)return -1; memcpy(epk,w+4,32); return 0; }
static int asym_ts(int fd, const uint8_t epk[32], const uint8_t key[16], int64_t *ts) {
    uint8_t ct[24],ad[ALEN],hdr[4]={FRAME_HANDSHAKE,FLAG_NONE,0,8};
    if(recv_all(fd,ct,24)!=0)return -1;
    memcpy(ad,hdr,4);memcpy(ad+4,epk,32);
    uint8_t tsb[8],n[16]={0}; if(aegis_decrypt(tsb,ct,8,ad,ALEN,n,key,ct+8)!=0)return -1;
    uint64_t tb=0;for(int i=0;i<8;i++)tb=(tb<<8)|tsb[i];*ts=(int64_t)tb;return 0;
}
static void asym_init_key(uint8_t key[16], const uint8_t ek[32], const uint8_t sk[32], const uint8_t pk[32]) {
    uint8_t ee[32],es[32]; ecdh_derive(ee,ek,pk);ecdh_derive(es,sk,pk);
    uint8_t b[68];memcpy(b,ee,32);memcpy(b+32,es,32);memcpy(b+64,"init",4);uint8_t h[32];sha256_h(h,b,68);
    memcpy(key,h,16);secure_memzero(h,32);secure_memzero(ee,32);secure_memzero(es,32);
}
static void asym_shared(uint8_t sh[32], const uint8_t ee[32], const uint8_t es[32], const uint8_t se[32]) {
    uint8_t b[102];memcpy(b,ee,32);memcpy(b+32,es,32);memcpy(b+64,se,32);memcpy(b+96,"shared",6);sha256_h(sh,b,102);
}
static void asym_resp(uint8_t k[16], const uint8_t sh[32]) { uint8_t b[36];memcpy(b,sh,32);memcpy(b+32,"resp",4);uint8_t h[32];sha256_h(h,b,36);memcpy(k,h,16);secure_memzero(h,32); }
static void asym_sess(session_keys_t *k, const uint8_t sh[32], const uint8_t ei[32], const uint8_t er[32]) {
    uint8_t b[103];memcpy(b,sh,32);memcpy(b+32,ei,32);memcpy(b+64,er,32);memcpy(b+96,"session",7);uint8_t h[32];sha256_h(h,b,103);
    memcpy(k->enc_key,h,16);memcpy(k->dec_key,h+16,16);secure_memzero(h,32);
}

int handshake_server(int fd, const uint8_t our_priv[32], const uint8_t peer_pub[32], int to, session_keys_t *keys) {
    uint8_t ek[32],epk[32],iepk[32],ik[16],rk[16],sh[32];int64_t its;
    int ret = -1;
    (void)to;  /* timeout handled by recv_all's poll() */
    if(asym_hdr(fd,iepk)!=0)return -1;
    {uint8_t ee[32],es[32];ecdh_derive(ee,our_priv,iepk);ecdh_derive(es,our_priv,peer_pub);uint8_t b[68];memcpy(b,ee,32);memcpy(b+32,es,32);memcpy(b+64,"init",4);uint8_t h[32];sha256_h(h,b,68);memcpy(ik,h,16);}
    if(asym_ts(fd,iepk,ik,&its)!=0) goto out;
    if(check_ts(its)!=0) goto out;
    if(ecdh_keygen(epk,ek)!=0) goto out;
    {uint8_t ee[32],es[32],se[32];ecdh_derive(ee,our_priv,iepk);ecdh_derive(es,our_priv,peer_pub);ecdh_derive(se,ek,peer_pub);asym_shared(sh,ee,es,se);secure_memzero(ee,32);secure_memzero(es,32);secure_memzero(se,32);}
    asym_sess(keys,sh,iepk,epk);{uint8_t t[16];memcpy(t,keys->enc_key,16);memcpy(keys->enc_key,keys->dec_key,16);memcpy(keys->dec_key,t,16);secure_memzero(t,16);}
    asym_resp(rk,sh);
    {int64_t ts=timestamp_now();int ok=asym_send(fd,epk,ts,rk);if(ok!=0||ts<0) goto out;}
    ret = 0;
out:
    secure_memzero(ek,32);secure_memzero(epk,32);secure_memzero(sh,32);
    secure_memzero(ik,16);secure_memzero(rk,16);secure_memzero(iepk,32);
    return ret;
}

int handshake_client(int fd, const uint8_t our_priv[32], const uint8_t peer_pub[32], int to, session_keys_t *keys) {
    uint8_t ek[32],epk[32],repk[32],ik[16],rk[16],sh[32];int64_t rts;
    int ret = -1;
    (void)to;  /* timeout handled by recv_all's poll() */
    if(ecdh_keygen(epk,ek)!=0)return -1;
    asym_init_key(ik,ek,our_priv,peer_pub);
    {int64_t ts=timestamp_now(); if(asym_send(fd,epk,ts,ik)!=0) goto out;}
    if(asym_hdr(fd,repk)!=0) goto out;
    {uint8_t ee[32],es[32],se[32];ecdh_derive(ee,ek,peer_pub);ecdh_derive(es,our_priv,peer_pub);ecdh_derive(se,our_priv,repk);asym_shared(sh,ee,es,se);secure_memzero(ee,32);secure_memzero(es,32);secure_memzero(se,32);}
    asym_resp(rk,sh);
    if(asym_ts(fd,repk,rk,&rts)!=0) goto out;
    if(check_ts(rts)!=0) goto out;
    asym_sess(keys,sh,epk,repk);
    ret = 0;
out:
    secure_memzero(sh,32);secure_memzero(ik,16);secure_memzero(rk,16);
    secure_memzero(ek,32);secure_memzero(epk,32);secure_memzero(repk,32);
    return ret;
}

/* ═══════════════════════════════════════════════════ key confirm */

int handshake_key_confirm_server(int fd, const session_keys_t *k, int to) {
    (void)to;  /* timeout handled by recv_all's poll() */
    uint8_t wb[FRAME_MAX_WIRE]; size_t wl=0;
    if(frame_build(wb,&wl,FRAME_KEYCONFIRM,FLAG_NONE,NULL,0,0,k->enc_key)!=0)return -1;
    return send_all(fd,wb,wl);
}
int handshake_key_confirm_client(int fd, const session_keys_t *k, int to) {
    (void)to;  /* timeout handled by recv_all's poll() */
    uint8_t wb[FRAME_HEADER_LEN+AEGIS_TAG_LEN];
    if(recv_all(fd,wb,sizeof(wb))!=0)return -1;
    uint8_t ty,fl,dum[1]; size_t dl;
    if(frame_parse(wb,sizeof(wb),&ty,&fl,dum,&dl,0,k->dec_key)!=0)return -1;
    return (ty==FRAME_KEYCONFIRM)?0:-1;
}

/* ═══════════════════════════════════════════════════ rekey */

int handshake_rekey(int fd, const uint8_t *psk, size_t plen, session_keys_t *keys, uint64_t *nc, int init) {
    uint8_t opriv[32],opub[32],ppub[32],sh[32],wb[FRAME_MAX_WIRE]; size_t wl;
    int ret = -1;
    if(ecdh_keygen(opub,opriv)!=0)return -1;
    if(init){
        if(frame_build(wb,&wl,FRAME_REKEY,FLAG_NONE,opub,32,*nc,keys->enc_key)!=0) goto out;
        (*nc)++;if(send_all(fd,wb,wl)!=0) goto out;
        uint8_t rb[FRAME_MAX_WIRE];if(recv_all(fd,rb,FRAME_HEADER_LEN+32+AEGIS_TAG_LEN)!=0) goto out;
        uint8_t rt,rf;size_t rl;
        if(frame_parse(rb,FRAME_HEADER_LEN+32+AEGIS_TAG_LEN,&rt,&rf,ppub,&rl,*nc,keys->dec_key)!=0) goto out;
        (*nc)++;
    }else{
        uint8_t rb[FRAME_MAX_WIRE];if(recv_all(fd,rb,FRAME_HEADER_LEN+32+AEGIS_TAG_LEN)!=0) goto out;
        uint8_t rt,rf;size_t rl;
        if(frame_parse(rb,FRAME_HEADER_LEN+32+AEGIS_TAG_LEN,&rt,&rf,ppub,&rl,*nc,keys->dec_key)!=0) goto out;
        (*nc)++;
        if(frame_build(wb,&wl,FRAME_REKEY,FLAG_NONE,opub,32,*nc,keys->enc_key)!=0) goto out;
        (*nc)++;if(send_all(fd,wb,wl)!=0) goto out;
    }
    if(ecdh_derive(sh,opriv,ppub)!=0) goto out;
    uint8_t nc2[16],ns[16];random_bytes(nc2,16);random_bytes(ns,16);
    size_t bl = plen + 32 + 32;
    uint8_t *b = (uint8_t*)malloc(bl);
    if (!b) goto out;
    uint8_t *p = b;
    /* psk may be NULL with plen=0 (auto-derived session PSK) */
    if (psk && plen > 0) { memcpy(p, psk, plen); p += plen; }
    memcpy(p, sh, 32); p += 32; memcpy(p, nc2, 16); p += 16; memcpy(p, ns, 16);
    uint8_t h[32],ek[16],dk[16];sha256_h(h,b,bl);free(b);memcpy(ek,h,16);memcpy(dk,h+16,16);secure_memzero(h,32);
    if(init){memcpy(keys->enc_key,ek,16);memcpy(keys->dec_key,dk,16);}
    else    {memcpy(keys->enc_key,dk,16);memcpy(keys->dec_key,ek,16);}
    secure_memzero(ek,16);secure_memzero(dk,16);secure_memzero(nc2,16);secure_memzero(ns,16);*nc=0;
    ret = 0;
out:
    secure_memzero(opriv,32);secure_memzero(sh,32);secure_memzero(ppub,32);
    return ret;
}
