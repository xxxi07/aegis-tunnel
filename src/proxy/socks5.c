/*
 * socks5.c — SOCKS5 CONNECT proxy implementation
 *
 * RFC 1928 SOCKS Protocol Version 5
 *
 * Handshake:
 *   Client → Server: [0x05, nmethods, methods...]
 *   Server → Client: [0x05, 0x00]  (no auth selected)
 *
 * Request:
 *   Client → Server: [0x05, 0x01, 0x00, ATYP, DST.ADDR, DST.PORT]
 *   Server → Client: [0x05, 0x00, 0x00, 0x01, 0x00*4, 0x00*2]  (success)
 *
 * After handshake, the socket is a raw TCP tunnel.
 */
#include "proxy/socks5.h"

#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* ─── Read exactly n bytes ─────────────────────────────────────── */

static int read_n(int fd, uint8_t *buf, size_t n)
{
    size_t got = 0;
    while (got < n) {
        ssize_t r = recv(fd, buf + got, n - got, 0);
        if (r <= 0) return -1;
        got += (size_t)r;
    }
    return 0;
}

/* ─── Send SOCKS5 reply ────────────────────────────────────────── */
/*
 * Reply format (RFC 1928 Section 6):
 *   [0x05, REP, 0x00, ATYP, BND.ADDR, BND.PORT]
 *
 * For CONNECT, BND fields are ignored by most clients.
 */
static int send_reply(int fd, uint8_t rep)
{
    uint8_t reply[10] = {
        0x05, rep, 0x00,          /* VER, REP, RSV */
        0x01,                      /* ATYP = IPv4 */
        0x00, 0x00, 0x00, 0x00,   /* BND.ADDR = 0.0.0.0 */
        0x00, 0x00                 /* BND.PORT = 0 */
    };
    return (send(fd, reply, sizeof(reply), MSG_NOSIGNAL) == sizeof(reply))
           ? 0 : -1;
}

/* ─── SOCKS5 accept ────────────────────────────────────────────── */

int socks5_accept(int client_fd,
                  char *host, size_t *host_len, uint16_t *port)
{
    uint8_t buf[262];  /* max: 4 + 1 + 255 + 2 */

    /* ── Step 1: Method negotiation ── */
    if (read_n(client_fd, buf, 2) != 0) return -1;
    if (buf[0] != 0x05) return -1;  /* VER = 5 */

    uint8_t nmethods = buf[1];
    if (nmethods == 0) return -1;
    if (read_n(client_fd, buf, nmethods) != 0) return -1;

    /* Select no-auth (0x00) — send method response */
    uint8_t method_resp[2] = { 0x05, 0x00 };
    if (send(client_fd, method_resp, 2, MSG_NOSIGNAL) != 2) return -1;

    /* ── Step 2: Request ── */
    /* Read: VER(1) + CMD(1) + RSV(1) + ATYP(1) = 4 bytes */
    if (read_n(client_fd, buf, 4) != 0) return -1;
    if (buf[0] != 0x05) return -1;  /* VER */
    if (buf[1] != 0x01) {           /* CMD = CONNECT only */
        send_reply(client_fd, 0x07);  /* command not supported */
        return -1;
    }

    uint8_t atyp = buf[3];

    /* Read address */
    if (atyp == 0x01) {
        /* IPv4: 4 bytes */
        if (read_n(client_fd, buf, 4) != 0) return -1;
        inet_ntop(AF_INET, buf, host, 256);
        *host_len = strlen(host);
    } else if (atyp == 0x03) {
        /* DOMAIN: 1-byte length + name */
        if (read_n(client_fd, buf, 1) != 0) return -1;
        uint8_t dlen = buf[0];
        if (dlen == 0) return -1;
        if (read_n(client_fd, (uint8_t *)host, dlen) != 0) return -1;
        host[dlen] = '\0';
        *host_len = dlen;
    } else {
        /* IPv6 (0x04) and others — not supported */
        send_reply(client_fd, 0x08);  /* address type not supported */
        return -1;
    }

    /* Read port (2 bytes, network order) */
    if (read_n(client_fd, buf, 2) != 0) return -1;
    *port = (uint16_t)((buf[0] << 8) | buf[1]);

    /* ── Step 3: Send success reply ── */
    if (send_reply(client_fd, 0x00) != 0) return -1;

    return 0;
}
