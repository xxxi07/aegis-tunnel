/*
 * frame_reader.c — Buffered TCP stream frame reader implementation
 *
 * The core challenge: TCP delivers a byte stream, not message
 * boundaries.  A single recv() might return:
 *   - Part of a frame header
 *   - A header plus part of the payload
 *   - A complete frame plus the start of the next one
 *   - Multiple complete frames
 *
 * This module buffers incoming data and extracts complete AEGIS-Tunnel
 * frames one at a time.  Incomplete frames remain in the buffer until
 * enough data arrives.
 *
 * Frame format (on the wire):
 *   [type:1][flags:1][length:2 BE][ciphertext:N][tag:16]
 *
 * Total wire bytes = 4 + N + 16, where N = payload length.
 */

#include "protocol/frame_reader.h"
#include "util/util.h"

#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* ─── Minimum frame size ───────────────────────────────────────── */
#define MIN_FRAME_SIZE  (FRAME_HEADER_LEN + AEGIS_TAG_LEN)  /* 4 + 16 = 20 */

/* ─── Initialize ────────────────────────────────────────────────── */

void frame_reader_init(frame_reader_t *fr, int fd)
{
    memset(fr, 0, sizeof(*fr));
    fr->fd = fd;
}

/* ─── Compact: move unprocessed data to front of buffer ─────────── */
/*
 * After extracting a frame, remaining bytes (next frame's start)
 * need to move to buf[0] for the next read cycle.
 */
static void compact(frame_reader_t *fr)
{
    if (fr->buf_off > 0 && fr->buf_off < fr->buf_len) {
        size_t remaining = fr->buf_len - fr->buf_off;
        memmove(fr->buf, fr->buf + fr->buf_off, remaining);
        fr->buf_len = remaining;
    } else if (fr->buf_off >= fr->buf_len) {
        fr->buf_len = 0;
    }
    fr->buf_off = 0;
}

/* ─── Read more data into buffer ────────────────────────────────── */
/*
 * Returns: 1 = got data, 0 = EOF/no-data, -1 = error
 */
static int fill_buffer(frame_reader_t *fr)
{
    if (fr->eof) return 0;

    /* Compact before reading to maximize space */
    compact(fr);

    size_t space = sizeof(fr->buf) - fr->buf_len;
    if (space == 0) {
        /* Buffer full — shouldn't happen with FRAME_MAX_WIRE size */
        return -1;
    }

    ssize_t n = recv(fr->fd, fr->buf + fr->buf_len, space, 0);
    if (n < 0) {
        if (errno == EINTR) return 1;  /* interrupted, try again */
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        return -1;
    }
    if (n == 0) {
        fr->eof = 1;
        return 0;
    }

    fr->buf_len += (size_t)n;
    return 1;
}

/* ─── Public: fill buffer from socket ───────────────────────────── */

int frame_reader_fill(frame_reader_t *fr)
{
    return fill_buffer(fr);
}

/* ─── Extract next complete frame ───────────────────────────────── */

int frame_reader_try_next(frame_reader_t *fr,
                          uint8_t *type, uint8_t *flags,
                          uint8_t *payload, size_t *plen,
                          uint64_t nonce_ctr,
                          const uint8_t key[AEGIS_KEY_LEN])
{
    /* Need at least a header to know the payload length */
    if (fr->buf_len - fr->buf_off < FRAME_HEADER_LEN) {
        return 0;  /* not enough data yet */
    }

    /* Parse header from current offset */
    const uint8_t *hdr = fr->buf + fr->buf_off;
    size_t p_len = (size_t)(((uint16_t)hdr[2] << 8) | hdr[3]);

    if (p_len > FRAME_MAX_PAYLOAD) return -1;

    size_t total_frame = FRAME_HEADER_LEN + p_len + AEGIS_TAG_LEN;

    /* Check if complete frame is available */
    if (fr->buf_len - fr->buf_off < total_frame) {
        return 0;  /* not enough data yet */
    }

    /* Complete frame available — decrypt it */
    const uint8_t *frame_start = fr->buf + fr->buf_off;

    int ret = frame_parse(frame_start, total_frame,
                          type, flags, payload, plen,
                          nonce_ctr, key);
    if (ret != 0) return -1;

    /* Advance past this frame */
    fr->buf_off += total_frame;

    return 1;
}

/* ─── Blocking read of next frame ───────────────────────────────── */

int frame_reader_next(frame_reader_t *fr,
                      uint8_t *type, uint8_t *flags,
                      uint8_t *payload, size_t *plen,
                      uint64_t nonce_ctr,
                      const uint8_t key[AEGIS_KEY_LEN])
{
    for (;;) {
        /* Try to extract from existing buffer */
        int ret = frame_reader_try_next(fr, type, flags,
                                        payload, plen,
                                        nonce_ctr, key);
        if (ret != 0) return ret;  /* got frame or error */

        /* Need more data */
        int fill = fill_buffer(fr);
        if (fill < 0) return -1;  /* error */
        if (fill == 0) {
            /* EOF with no complete frame — check for partial */
            if (fr->buf_len - fr->buf_off > 0) {
                return -1;  /* truncated frame */
            }
            return 0;  /* clean EOF */
        }
        /* Got more data — loop back to try extraction again */
    }
}
