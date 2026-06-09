/*
 * keyfile.c — Key file I/O for asymmetric keypairs
 */
#include "protocol/keyfile.h"
#include "protocol/ecdh.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int keyfile_generate(const char *priv_path, const char *pub_path)
{
    uint8_t pub[ECDH_PUBKEY_LEN];
    uint8_t priv[ECDH_PRIVKEY_LEN];

    if (ecdh_keygen(pub, priv) != 0) return -1;

    /* Write private key (restrictive permissions) */
    int fd = open(priv_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) { fprintf(stderr, "Cannot create %s: %s\n", priv_path, strerror(errno)); return -1; }
    if (write(fd, priv, ECDH_PRIVKEY_LEN) != ECDH_PRIVKEY_LEN) { close(fd); return -1; }
    close(fd);

    /* Write public key (world-readable) */
    fd = open(pub_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { fprintf(stderr, "Cannot create %s: %s\n", pub_path, strerror(errno)); return -1; }
    if (write(fd, pub, ECDH_PUBKEY_LEN) != ECDH_PUBKEY_LEN) { close(fd); return -1; }
    close(fd);

    return 0;
}

int keyfile_load(uint8_t key[KEYFILE_KEY_LEN], const char *path)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;

    ssize_t n = read(fd, key, KEYFILE_KEY_LEN);
    close(fd);

    if (n != KEYFILE_KEY_LEN) {
        fprintf(stderr, "Key file %s: expected %d bytes, got %zd\n",
                path, KEYFILE_KEY_LEN, n);
        return -1;
    }
    return 0;
}

int keyfile_load_private(uint8_t key[KEYFILE_KEY_LEN], const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0) {
        fprintf(stderr, "Cannot stat private key %s: %s\n", path, strerror(errno));
        return -1;
    }
    if ((st.st_mode & 0777) != 0600 && (st.st_mode & 0777) != 0400) {
        fprintf(stderr, "WARNING: private key %s has insecure permissions %04o\n"
                        "         Expected 0600 or 0400. Fix: chmod 400 %s\n",
                path, (unsigned)(st.st_mode & 0777), path);
        /* Continue anyway — just warn */
    }
    return keyfile_load(key, path);
}

int keyfile_load_public(uint8_t key[KEYFILE_KEY_LEN], const char *path)
{
    return keyfile_load(key, path);
}
