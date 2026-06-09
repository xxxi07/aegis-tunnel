/*
 * handshake.c — AEGIS-Tunnel handshake protocols
 * PSK symmetric + Asymmetric (WireGuard model, 3-DH)
 */
#include "protocol/ecdh.h"
#include "protocol/handshake.h"
#include "tunnel/tunnel.h"
#include "util/util.h"
#include <errno.h>
#include <openssl/evp.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
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
static void set_socket_timeout(int fd, int ms) { if(ms<=0)return; struct timeval tv={.tv_sec=ms/1000,.tv_usec=(ms%1000)*1000}; setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv)); }
static int send_all(int fd, const uint8_t *b, size_t n) { size_t s=0; while(s<n){ ssize_t r=send(fd,b+s,n-s,0); if(r<0){if(errno==EINTR)continue;return -1;} if(r==0)return -1; s+=(size_t)r;} return 0; }
static int recv_all(int fd, uint8_t *b, size_t n) { size_t r=0; while(r<n){ ssize_t x=recv(fd,b+r,n-r,0); if(x<0){if(errno==EINTR)continue;return -1;} if(x==0)return -1; r+=(size_t)x;} return 0; }

/* ═══════════════════════════════════════════════════ PSK symmetric handshake */

static const char *PSK_DOMAIN = "AEGIS-TUNNEL-HANDSHAKE-V2-ECDH";
static int psk_init_key(uint8_t ik[16], const uint8_t *psk, size_t plen) {
    size_t dl=strlen(PSK_DOMAIN), bl=plen+dl; uint8_t *b=(uint8_t*)malloc(bl); if(!b)return -1;
    memcpy(b,psk,plen); memcpy(b+plen,PSK_DOMAIN,dl); uint8_t h[32]; sha256_h(h,b,bl); free(b);
    memcpy(ik,h,16); secure_memzero(h,32); return 0;
}
static int psk_session(session_keys_t *k, const uint8_t *psk, size_t plen, const uint8_t sh[32], const uint8_t nc[16], const uint8_t ns[16]) {
    size_t bl=plen+64; uint8_t *b=(uint8_t*)malloc(bl),*p=b;
    memcpy(p,psk,plen);p+=plen; memcpy(p,sh,32);p+=32; memcpy(p,nc,16);p+=16; memcpy(p,ns,16);
    uint8_t h[32]; sha256_h(h,b,bl); free(b);
    memcpy(k->enc_key,h,16); memcpy(k->dec_key,h+16,16); secure_memzero(h,32); return 0;
}
static void psk_build(uint8_t pl[56], const uint8_t nonce[16], int64_t ts, const uint8_t pub[32]) {
    memcpy(pl,nonce,16); uint64_t tb=(uint64_t)ts; for(int i=0;i<8;i++)pl[16+7-i]=(uint8_t)(tb>>(i*8)); memcpy(pl+24,pub,32);
}
static void psk_extract(const uint8_t pl[56], uint8_t nonce[16], int64_t *ts, uint8_t pub[32]) {
    memcpy(nonce,pl,16); uint64_t tb=0; for(int i=0;i<8;i++)tb=(tb<<8)|pl[16+i]; *ts=(int64_t)tb; memcpy(pub,pl+24,32);
}
static int psk_send(int fd, const uint8_t nonce[16], int64_t ts, const uint8_t pub[32], const uint8_t ik[16]) {
    uint8_t pl[56]; psk_build(pl,nonce,ts,pub); uint8_t wb[FRAME_MAX_WIRE]; size_t wl=0;
    if(frame_build(wb,&wl,FRAME_HANDSHAKE,FLAG_NONE,pl,56,0,ik)!=0)return -1;
    return send_all(fd,wb,wl);
}
static int psk_recv(int fd, uint8_t nonce[16], int64_t *ts, uint8_t pub[32], const uint8_t ik[16]) {
    uint8_t wb[FRAME_HEADER_LEN+56+AEGIS_TAG_LEN]; if(recv_all(fd,wb,sizeof(wb))!=0)return -1;
    uint8_t ty,fl,pl[56]; size_t plen;
    if(frame_parse(wb,sizeof(wb),&ty,&fl,pl,&plen,0,ik)!=0)return -1;
    if(ty!=FRAME_HANDSHAKE||plen!=56)return -1;
    psk_extract(pl,nonce,ts,pub); return 0;
}

int handshake_server(int fd, const uint8_t *psk, size_t plen, int timeout_ms, session_keys_t *keys) {
    uint8_t ik[16],epriv[32],epub[32],cpub[32],cn[16],sn[16],sh[32]; int64_t cts;
    int ret = -1;
    set_socket_timeout(fd,timeout_ms); if(plen<16||psk_init_key(ik,psk,plen)!=0)return -1;
    if(psk_recv(fd,cn,&cts,cpub,ik)!=0) goto out;
    if(check_ts(cts)!=0) goto out;
    if(ecdh_keygen(epub,epriv)!=0||random_bytes(sn,16)!=0) goto out;
    if(ecdh_derive(sh,epriv,cpub)!=0){secure_memzero(epriv,32);goto out;}
    secure_memzero(epriv,32);
    if(psk_session(keys,psk,plen,sh,cn,sn)!=0) goto out;
    {uint8_t t[16];memcpy(t,keys->enc_key,16);memcpy(keys->enc_key,keys->dec_key,16);memcpy(keys->dec_key,t,16);secure_memzero(t,16);}
    int64_t sts=timestamp_now(); int r=psk_send(fd,sn,sts,epub,ik);
    if(r==0&&sts>=0) ret = 0;
out:
    secure_memzero(sh,32);secure_memzero(cn,16);secure_memzero(sn,16);
    secure_memzero(epub,32);secure_memzero(cpub,32);secure_memzero(ik,16);
    return ret;
}

int handshake_client(int fd, const uint8_t *psk, size_t plen, int timeout_ms, session_keys_t *keys) {
    uint8_t ik[16],epriv[32],epub[32],spub[32],cn[16],sn[16],sh[32]; int64_t sts;
    int ret = -1;
    set_socket_timeout(fd,timeout_ms); if(plen<16||psk_init_key(ik,psk,plen)!=0)return -1;
    if(ecdh_keygen(epub,epriv)!=0||random_bytes(cn,16)!=0) goto out;
    int64_t cts=timestamp_now();
    if(psk_send(fd,cn,cts,epub,ik)!=0) goto out;
    if(psk_recv(fd,sn,&sts,spub,ik)!=0) goto out;
    if(check_ts(sts)!=0) goto out;
    if(ecdh_derive(sh,epriv,spub)!=0) goto out;
    secure_memzero(epriv,32);
    if(psk_session(keys,psk,plen,sh,cn,sn)!=0) goto out;
    ret = 0;
out:
    secure_memzero(sh,32);secure_memzero(cn,16);secure_memzero(sn,16);
    secure_memzero(epub,32);secure_memzero(spub,32);secure_memzero(ik,16);
    secure_memzero(epriv,32);
    return ret;
}

/* ═══════════════════════════════════════════════════ key confirm + rekey */

int handshake_key_confirm_server(int fd, const session_keys_t *k, int to) {
    set_socket_timeout(fd,to); uint8_t wb[FRAME_MAX_WIRE]; size_t wl=0;
    if(frame_build(wb,&wl,FRAME_KEYCONFIRM,FLAG_NONE,NULL,0,0,k->enc_key)!=0)return -1;
    return send_all(fd,wb,wl);
}
int handshake_key_confirm_client(int fd, const session_keys_t *k, int to) {
    set_socket_timeout(fd,to); uint8_t wb[FRAME_HEADER_LEN+AEGIS_TAG_LEN];
    if(recv_all(fd,wb,sizeof(wb))!=0)return -1;
    uint8_t ty,fl,dum[1]; size_t dl;
    if(frame_parse(wb,sizeof(wb),&ty,&fl,dum,&dl,0,k->dec_key)!=0)return -1;
    return (ty==FRAME_KEYCONFIRM)?0:-1;
}
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
    size_t bl=plen+32+32;uint8_t *b=(uint8_t*)malloc(bl),*p=b;
    memcpy(p,psk,plen);p+=plen;memcpy(p,sh,32);p+=32;memcpy(p,nc2,16);p+=16;memcpy(p,ns,16);
    uint8_t h[32],ek[16],dk[16];sha256_h(h,b,bl);free(b);memcpy(ek,h,16);memcpy(dk,h+16,16);secure_memzero(h,32);
    if(init){memcpy(keys->enc_key,ek,16);memcpy(keys->dec_key,dk,16);}
    else    {memcpy(keys->enc_key,dk,16);memcpy(keys->dec_key,ek,16);}
    secure_memzero(ek,16);secure_memzero(dk,16);secure_memzero(nc2,16);secure_memzero(ns,16);*nc=0;
    ret = 0;
out:
    secure_memzero(opriv,32);secure_memzero(sh,32);secure_memzero(ppub,32);
    return ret;
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

int handshake_asymmetric_client(int fd, const uint8_t our_priv[32], const uint8_t peer_pub[32], int to, session_keys_t *keys) {
    uint8_t ek[32],epk[32],repk[32],ik[16],rk[16],sh[32];int64_t rts;
    int ret = -1;
    set_socket_timeout(fd,to);
    if(ecdh_keygen(epk,ek)!=0)return -1;
    asym_init_key(ik,ek,our_priv,peer_pub);
    {int64_t ts=timestamp_now();
     if(asym_send(fd,epk,ts,ik)!=0) goto out;}
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

int handshake_asymmetric_server(int fd, const uint8_t our_priv[32], const uint8_t peer_pub[32], int to, session_keys_t *keys) {
    uint8_t ek[32],epk[32],iepk[32],ik[16],rk[16],sh[32];int64_t its;
    int ret = -1;
    set_socket_timeout(fd,to);
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
