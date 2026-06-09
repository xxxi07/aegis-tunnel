/*
 * util.c — Utility function implementations
 */

#include "util/util.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* ─── hex_dump ─────────────────────────────────────────────────── */

void hex_dump(const char *label, const uint8_t *buf, size_t len)
{
    fprintf(stderr, "%s (%zu bytes):\n", label ? label : "hex", len);
    for (size_t i = 0; i < len; i++) {
        if (i % 16 == 0) {
            fprintf(stderr, "  %04zx: ", i);
        }
        fprintf(stderr, "%02x ", buf[i]);
        if (i % 16 == 7) {
            fprintf(stderr, " ");  /* extra space in middle */
        }
        if (i % 16 == 15) {
            fprintf(stderr, "\n");
        }
    }
    if (len % 16 != 0) {
        fprintf(stderr, "\n");
    }
}

/* ─── random_bytes ─────────────────────────────────────────────── */

int random_bytes(uint8_t *buf, size_t len)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return -1;
    }

    size_t total = 0;
    while (total < len) {
        ssize_t n = read(fd, buf + total, len - total);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            close(fd);
            return -1;
        }
        if (n == 0) {
            /* /dev/urandom should never return EOF — treat as error */
            close(fd);
            return -1;
        }
        total += (size_t)n;
    }

    close(fd);
    return 0;
}

/* ─── secure_memzero ───────────────────────────────────────────── */

#ifdef HAVE_EXPLICIT_BZERO
#include <string.h>
#endif

void secure_memzero(void *ptr, size_t len)
{
#ifdef HAVE_EXPLICIT_BZERO
    explicit_bzero(ptr, len);
#else
    /*
     * Use volatile pointer to prevent the compiler from optimizing
     * away the memset.  The compiler cannot prove that a write
     * through a volatile pointer has no observable side effects.
     */
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len--) {
        *p++ = 0;
    }
    /*
     * Compiler barrier: prevents reordering or elimination of
     * the preceding writes.
     */
    __asm__ __volatile__("" : : "r"(ptr) : "memory");
#endif
}

/* ─── timestamp_now ────────────────────────────────────────────── */

int64_t timestamp_now(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        return -1;
    }
    return (int64_t)ts.tv_sec;
}

/* ─── memcmp_constant ──────────────────────────────────────────── */

int memcmp_constant(const uint8_t *a, const uint8_t *b, size_t len)
{
    /*
     * Accumulate differences via bitwise OR-of-XOR.
     * No branches on data values — every byte is always compared.
     * The final `diff` will be 0 if and only if all bytes matched.
     */
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (a[i] ^ b[i]);
    }
    /*
     * Compiler barrier: ensure diff is fully computed before return.
     */
    __asm__ __volatile__("" : : "r"(diff) : "memory");
    return (int)diff;
}
