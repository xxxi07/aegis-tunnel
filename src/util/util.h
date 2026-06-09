/*
 * util.h — Utility functions for aegis-tunnel
 *
 * Provides cryptographically-safe random number generation,
 * constant-time memory comparison, secure memory zeroing,
 * hex dump for debugging, and timestamp functions.
 */
#ifndef UTIL_H
#define UTIL_H

#include <stddef.h>
#include <stdint.h>

/*
 * Print a hex dump of `buf` to stderr.
 * Used for debugging only — never prints sensitive data in production.
 */
void hex_dump(const char *label, const uint8_t *buf, size_t len);

/*
 * Fill `buf` with `len` cryptographically secure random bytes
 * read from /dev/urandom.
 *
 * Retries on partial reads.  Returns 0 on success, -1 on error.
 */
int  random_bytes(uint8_t *buf, size_t len);

/*
 * Zero `len` bytes starting at `ptr` without the compiler
 * optimizing the operation away.
 *
 * Uses a volatile pointer to prevent dead-store elimination.
 * For sensitive data: keys, nonces, plaintext buffers.
 */
void secure_memzero(void *ptr, size_t len);

/*
 * Get the current Unix timestamp in seconds.
 * Uses clock_gettime(CLOCK_REALTIME).
 */
int64_t timestamp_now(void);

/*
 * Constant-time memory comparison.
 *
 * Returns 0 if `a` and `b` are equal for `len` bytes,
 * non-zero otherwise.  The comparison does not short-circuit —
 * every byte is compared regardless of early differences.
 *
 * CRITICAL: Always use this (never memcmp!) for comparing
 * authentication tags, MACs, or any other security-sensitive data.
 */
int   memcmp_constant(const uint8_t *a, const uint8_t *b, size_t len);

#endif /* UTIL_H */
