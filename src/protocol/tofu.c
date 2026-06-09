/*
 * tofu.c — TOFU key management implementation
 */
#include "protocol/tofu.h"
#include "protocol/ecdh.h"
#include "protocol/keyfile.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define TOFU_SUBDIR  "/.aegis-tunnel"

static char g_tofu_dir[512] = "";

const char *tofu_dir(void)
{
    if (g_tofu_dir[0] == '\0') {
        const char *home = getenv("HOME");
        if (!home) home = "/tmp";
        snprintf(g_tofu_dir, sizeof(g_tofu_dir), "%s" TOFU_SUBDIR, home);
    }
    return g_tofu_dir;
}

static int ensure_dir(void)
{
    const char *dir = tofu_dir();
    struct stat st;
    if (stat(dir, &st) != 0) {
        if (mkdir(dir, 0700) != 0 && errno != EEXIST) {
            fprintf(stderr, "tofu: cannot create %s: %s\n", dir, strerror(errno));
            return -1;
        }
    }
    return 0;
}

int tofu_ensure_keypair(uint8_t priv_out[TOFU_KEY_LEN],
                        uint8_t pub_out[TOFU_KEY_LEN])
{
    if (ensure_dir() != 0) return -1;

    const char *dir = tofu_dir();
    char priv_path[512], pub_path[512];
    snprintf(priv_path, sizeof(priv_path), "%s/private.key", dir);
    snprintf(pub_path, sizeof(pub_path), "%s/public.key", dir);

    /* Check if keys already exist */
    if (keyfile_load_private(priv_out, priv_path) == 0 &&
        keyfile_load_public(pub_out, pub_path) == 0) {
        return 0;  /* already have keys */
    }

    /* Generate new keypair */
    fprintf(stderr, "[tofu] generating new keypair in %s...\n", dir);
    if (keyfile_generate(priv_path, pub_path) != 0) return -1;

    /* Load the generated keys */
    if (keyfile_load_private(priv_out, priv_path) != 0) return -1;
    if (keyfile_load_public(pub_out, pub_path) != 0) return -1;

    fprintf(stderr, "[tofu] keypair ready\n");
    return 0;
}

int tofu_save_peer(const char *host, int port,
                   const uint8_t pubkey[TOFU_KEY_LEN])
{
    if (ensure_dir() != 0) return -1;

    char path[512];
    snprintf(path, sizeof(path), "%s/known_hosts", tofu_dir());

    /* Check if this host:port already has an entry */
    char line[512];
    char match_prefix[128];
    snprintf(match_prefix, sizeof(match_prefix), "%s:%d ", host, port);

    /* Read existing file, replace or append */
    char tmp_path[512];
    snprintf(tmp_path, sizeof(tmp_path), "%s/known_hosts.tmp", tofu_dir());

    FILE *in = fopen(path, "r");
    FILE *out = fopen(tmp_path, "w");
    if (!out) return -1;

    int found = 0;
    if (in) {
        while (fgets(line, sizeof(line), in)) {
            if (strncmp(line, match_prefix, strlen(match_prefix)) == 0) {
                /* Replace this line */
                found = 1;
            } else {
                fputs(line, out);
            }
        }
        fclose(in);
    }

    /* Write new/updated entry */
    fprintf(out, "%s ", match_prefix);
    for (int i = 0; i < 32; i++) fprintf(out, "%02x", pubkey[i]);
    fprintf(out, "\n");

    fclose(out);
    rename(tmp_path, path);

    fprintf(stderr, "[tofu] %s peer %s:%d\n",
            found ? "updated" : "saved", host, port);
    return 0;
}

int tofu_load_peer(const char *host, int port,
                   uint8_t pubkey[TOFU_KEY_LEN])
{
    char path[512];
    snprintf(path, sizeof(path), "%s/known_hosts", tofu_dir());

    FILE *fp = fopen(path, "r");
    if (!fp) return 0;  /* no known_hosts yet → first connection */

    char match_prefix[128];
    snprintf(match_prefix, sizeof(match_prefix), "%s:%d ", host, port);

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, match_prefix, strlen(match_prefix)) == 0) {
            fclose(fp);
            /* Parse hex pubkey */
            char *hex = line + strlen(match_prefix);
            for (int i = 0; i < 32; i++) {
                unsigned int byte;
                if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
                pubkey[i] = (uint8_t)byte;
            }
            return 1;  /* found */
        }
    }
    fclose(fp);
    return 0;  /* not found → first connection */
}

/*
 * Exchange static public keys via encrypted FRAME_TOFU.
 *
 * Wire format: frame header + 32-byte pubkey payload + 16-byte tag.
 * Encrypted with session key (AEGIS-128).
 */
#include "protocol/handshake.h"
#include "tunnel/tunnel.h"   /* for frame_build / frame_parse */
#include <errno.h>
#include <sys/socket.h>
#include <unistd.h>

int tofu_exchange_keys(int fd,
                       const char *host, int port,
                       const uint8_t our_pubkey[TOFU_KEY_LEN],
                       const uint8_t enc_key[16],
                       const uint8_t dec_key[16],
                       uint64_t *nonce_ctr,
                       int is_server)
{
    uint8_t peer_pub[TOFU_KEY_LEN];

    if (is_server) {
        /* Server: receive first, then send */
        uint8_t wb[FRAME_HEADER_LEN + TOFU_KEY_LEN + AEGIS_TAG_LEN];
        size_t got = 0;
        while (got < sizeof(wb)) {
            ssize_t n = recv(fd, wb + got, sizeof(wb) - got, 0);
            if (n < 0) { if (errno == EINTR) continue; return -1; }
            if (n == 0) return -1;
            got += (size_t)n;
        }
        uint64_t rx_nonce = *nonce_ctr;
        (*nonce_ctr)++;
        uint8_t type, flags; size_t plen = 0;
        if (frame_parse(wb, sizeof(wb), &type, &flags, peer_pub, &plen, rx_nonce, dec_key) != 0) return -1;
        if (type != FRAME_TOFU || plen != TOFU_KEY_LEN) return -1;

        tofu_save_peer(host, port, peer_pub);

        /* Send our pubkey */
        uint8_t swb[FRAME_MAX_WIRE]; size_t swl = 0;
        uint64_t tx_nonce = *nonce_ctr;
        (*nonce_ctr)++;
        if (frame_build(swb, &swl, FRAME_TOFU, FLAG_NONE, our_pubkey, TOFU_KEY_LEN, tx_nonce, enc_key) != 0) return -1;
        size_t sent = 0;
        while (sent < swl) {
            ssize_t n = send(fd, swb + sent, swl - sent, MSG_NOSIGNAL);
            if (n < 0) { if (errno == EINTR) continue; return -1; }
            sent += (size_t)n;
        }
    } else {
        /* Client: send first, then receive */
        uint8_t swb[FRAME_MAX_WIRE]; size_t swl = 0;
        uint64_t tx_nonce = *nonce_ctr;
        (*nonce_ctr)++;
        if (frame_build(swb, &swl, FRAME_TOFU, FLAG_NONE, our_pubkey, TOFU_KEY_LEN, tx_nonce, enc_key) != 0) return -1;
        size_t sent = 0;
        while (sent < swl) {
            ssize_t n = send(fd, swb + sent, swl - sent, MSG_NOSIGNAL);
            if (n < 0) { if (errno == EINTR) continue; return -1; }
            sent += (size_t)n;
        }

        uint8_t wb[FRAME_HEADER_LEN + TOFU_KEY_LEN + AEGIS_TAG_LEN];
        size_t got = 0;
        while (got < sizeof(wb)) {
            ssize_t n = recv(fd, wb + got, sizeof(wb) - got, 0);
            if (n < 0) { if (errno == EINTR) continue; return -1; }
            if (n == 0) return -1;
            got += (size_t)n;
        }
        uint64_t rx_nonce = *nonce_ctr;
        (*nonce_ctr)++;
        uint8_t type, flags; size_t plen = 0;
        if (frame_parse(wb, sizeof(wb), &type, &flags, peer_pub, &plen, rx_nonce, dec_key) != 0) return -1;
        if (type != FRAME_TOFU || plen != TOFU_KEY_LEN) return -1;

        tofu_save_peer(host, port, peer_pub);
    }

    return 0;
}
