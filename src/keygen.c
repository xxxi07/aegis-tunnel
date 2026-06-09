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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    const char *dir = (argc > 1) ? argv[1] : ".";

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
