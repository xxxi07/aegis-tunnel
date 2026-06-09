/*
 * frame_reader.h — Buffered TCP stream frame reader
 *
 * TCP is a byte-stream protocol.  Multiple AEGIS-Tunnel frames can
 * arrive in a single recv() call, or a single frame can be split
 * across multiple recv() calls.  This module provides buffered,
 * boundary-aware frame extraction.
 *
 * Usage:
 *   frame_reader_t fr;
 *   frame_reader_init(&fr, fd);
 *
 *   while ((ret = frame_reader_next(&fr, &type, &flags,
 *                                    payload, &plen, nonce, key)) > 0) {
 *       // process one complete decrypted frame
 *   }
 *   // ret == 0: clean EOF, ret < 0: error
 */
#ifndef FRAME_READER_H
#define FRAME_READER_H

#include "tunnel/tunnel.h"
#include <stddef.h>
#include <stdint.h>

/* ── Frame reader state ────────────────────────────────────────── */

typedef struct {
    int   fd;                          /* socket to read from */
    uint8_t buf[FRAME_MAX_WIRE];       /* input buffer */
    size_t buf_len;                    /* bytes currently buffered */
    size_t buf_off;                    /* next unprocessed byte offset */
    int    eof;                         /* set when peer closed */
} frame_reader_t;

/* ── API ───────────────────────────────────────────────────────── */

/* Initialize a frame reader for a socket. */
void frame_reader_init(frame_reader_t *fr, int fd);

/*
 * Read and return the next complete, decrypted frame from the stream.
 *
 * Blocks until a complete frame arrives or the peer disconnects.
 * Multiple calls to recv() may be made internally — each call
 * reads as much TCP data as is available into the buffer, then
 * attempts to extract a complete frame.
 *
 * Parameters:
 *   fr:     initialized frame reader
 *   type:   [out] frame type (FRAME_DATA, FRAME_KEEPALIVE, FRAME_CLOSE)
 *   flags:  [out] frame flags
 *   payload:[out] decrypted payload buffer (≥ FRAME_MAX_PAYLOAD)
 *   plen:   [out] decrypted payload length
 *   nonce_ctr: nonce counter value for this frame
 *   key:     decryption key (16 bytes)
 *
 * Returns:
 *    1 — got a complete frame (payload contains decrypted data)
 *    0 — EOF (peer disconnected cleanly)
 *   -1 — authentication failure or protocol error
 */
int frame_reader_next(frame_reader_t *fr,
                      uint8_t *type, uint8_t *flags,
                      uint8_t *payload, size_t *plen,
                      uint64_t nonce_ctr,
                      const uint8_t key[AEGIS_KEY_LEN]);

/*
 * Read available data from the socket into the internal buffer.
 * Should be called when poll()/select() indicates fd is readable.
 *
 * Returns: 1=data read, 0=EOF, -1=error
 */
int frame_reader_fill(frame_reader_t *fr);

/*
 * Non-blocking variant: returns 0 immediately if no complete frame
 * is available in the buffer, without calling recv().
 *
 * Returns:
 *    1 — got a complete frame
 *    0 — no complete frame available yet
 *   -1 — authentication failure or protocol error
 */
int frame_reader_try_next(frame_reader_t *fr,
                          uint8_t *type, uint8_t *flags,
                          uint8_t *payload, size_t *plen,
                          uint64_t nonce_ctr,
                          const uint8_t key[AEGIS_KEY_LEN]);

#endif /* FRAME_READER_H */
