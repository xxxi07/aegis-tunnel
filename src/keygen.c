/*
 * keygen.c — AEGIS-Tunnel key generation utility
 *
 * Generates X25519 keypairs for asymmetric authentication.
 *
 * Usage:
 *   aegis-tunnel-keygen [output_dir]
 *
 * Creates:
 *   private.key — 32 bytes, chmod 400 (keep secret on this machine)
 *   public.key  — 32 bytes, chmod 644 (share with peer)
 *
 * Also prints the public key as hex for easy sharing.
 */
#include "protocol/keyfile.h"
#include "protocol/ecdh.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifndef __linux__  /* Linux mkdir takes mode; others may define elsewhere */
#include <sys/stat.h>
#endif

/*
 * Create directory at `path` with 0755 permissions, like mkdir -p.
 * Returns 0 on success, -1 on error (reports to stderr).
 */
static int mkdir_p(const char *path)
{
    char tmp[512];
    size_t len = strlen(path);
    if (len >= sizeof(tmp) || len == 0) {
        fprintf(stderr, "mkdir_p: path too long or empty\n");
        return -1;
    }
    memcpy(tmp, path, len + 1);

    for (size_t i = 1; i < len; i++) {  /* start at 1 to skip root '/' */
        if (tmp[i] == '/') {
            tmp[i] = '\0';
            struct stat st;
            if (stat(tmp, &st) != 0) {
                if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
                    fprintf(stderr, "mkdir: cannot create '%s': %s\n",
                            tmp, strerror(errno));
                    return -1;
                }
            }
            tmp[i] = '/';
        }
    }
    /* Final component */
    struct stat st;
    if (stat(path, &st) != 0) {
        if (mkdir(path, 0755) != 0 && errno != EEXIST) {
            fprintf(stderr, "mkdir: cannot create '%s': %s\n",
                    path, strerror(errno));
            return -1;
        }
    }
    return 0;
}

int main(int argc, char **argv)
{
    const char *dir = (argc > 1) ? argv[1] : ".";

    /* Auto-create output directory if missing */
    if (mkdir_p(dir) != 0) {
        return 1;
    }

    char priv_path[512], pub_path[512];
    snprintf(priv_path, sizeof(priv_path), "%s/private.key", dir);
    snprintf(pub_path, sizeof(pub_path), "%s/public.key", dir);

    if (keyfile_generate(priv_path, pub_path) != 0) {
        fprintf(stderr, "Key generation failed\n");
        return 1;
    }

    /* Read back and show public key as hex */
    uint8_t pub[32];
    if (keyfile_load_public(pub, pub_path) == 0) {
        printf("public key (hex): ");
        for (int i = 0; i < 32; i++) printf("%02x", pub[i]);
        printf("\n");
    }

    printf("\nGenerated:\n");
    printf("  %s  (chmod 400 — KEEP SECRET on this machine)\n", priv_path);
    printf("  %s  (chmod 644 — share with peer)\n", pub_path);
    printf("\nConfiguration:\n");
    printf("  This machine:  private-key = %s\n", priv_path);
    printf("  Peer machine:  peer-public-key = %s\n", pub_path);
    printf("\n");

    return 0;
}
