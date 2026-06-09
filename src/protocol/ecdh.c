/*
 * ecdh.c — X25519 ECDH key exchange implementation
 *
 * Uses OpenSSL EVP_PKEY X25519 API (available since OpenSSL 1.1.1).
 * The shared secret is hashed with SHA256 to produce a uniform key.
 */
#include "protocol/ecdh.h"
#include "util/util.h"

#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

int ecdh_keygen(uint8_t pubkey[ECDH_PUBKEY_LEN],
                uint8_t privkey[ECDH_PRIVKEY_LEN])
{
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY     *pkey = NULL;

    /* Create X25519 key generation context */
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!pctx) goto fail;

    if (EVP_PKEY_keygen_init(pctx) <= 0) goto fail;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) goto fail;

    /* Extract raw private key (32 bytes) */
    size_t privlen = ECDH_PRIVKEY_LEN;
    if (EVP_PKEY_get_raw_private_key(pkey, privkey, &privlen) <= 0)
        goto fail;

    /* Extract raw public key (32 bytes) */
    size_t publen = ECDH_PUBKEY_LEN;
    if (EVP_PKEY_get_raw_public_key(pkey, pubkey, &publen) <= 0)
        goto fail;

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    return 0;

fail:
    if (pkey) EVP_PKEY_free(pkey);
    if (pctx) EVP_PKEY_CTX_free(pctx);
    return -1;
}

int ecdh_derive(uint8_t shared_secret[ECDH_SHARED_LEN],
                const uint8_t our_privkey[ECDH_PRIVKEY_LEN],
                const uint8_t peer_pubkey[ECDH_PUBKEY_LEN])
{
    EVP_PKEY     *our_key  = NULL;
    EVP_PKEY     *peer_key = NULL;
    EVP_PKEY_CTX *derive_ctx = NULL;
    uint8_t       raw_shared[32];
    size_t        shared_len = sizeof(raw_shared);

    /* Build our private key */
    our_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL,
                                           our_privkey, ECDH_PRIVKEY_LEN);
    if (!our_key) goto fail;

    /* Build peer's public key */
    peer_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL,
                                           peer_pubkey, ECDH_PUBKEY_LEN);
    if (!peer_key) goto fail;

    /* Derive shared secret */
    derive_ctx = EVP_PKEY_CTX_new(our_key, NULL);
    if (!derive_ctx) goto fail;

    if (EVP_PKEY_derive_init(derive_ctx) <= 0) goto fail;
    if (EVP_PKEY_derive_set_peer(derive_ctx, peer_key) <= 0) goto fail;
    if (EVP_PKEY_derive(derive_ctx, raw_shared, &shared_len) <= 0) goto fail;

    /* Hash the shared secret for uniform key material */
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    unsigned int mdlen = 0;
    if (!mdctx) goto fail;

    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, raw_shared, shared_len);
    EVP_DigestFinal_ex(mdctx, shared_secret, &mdlen);
    EVP_MD_CTX_free(mdctx);

    /* Wipe raw point */
    secure_memzero(raw_shared, sizeof(raw_shared));

    EVP_PKEY_free(our_key);
    EVP_PKEY_free(peer_key);
    EVP_PKEY_CTX_free(derive_ctx);
    return (mdlen == ECDH_SHARED_LEN) ? 0 : -1;

fail:
    if (our_key) EVP_PKEY_free(our_key);
    if (peer_key) EVP_PKEY_free(peer_key);
    if (derive_ctx) EVP_PKEY_CTX_free(derive_ctx);
    return -1;
}
