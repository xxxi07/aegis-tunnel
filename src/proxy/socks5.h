/*
 * socks5.h — Minimal SOCKS5 proxy server (RFC 1928)
 *
 * Implements the SOCKS5 CONNECT command (TCP tunneling) without
 * authentication.  Existing applications can use this proxy
 * without any code changes — just point their SOCKS5 client
 * at the tunnel's local port.
 *
 * Supported:
 *   - SOCKS5 CONNECT (establish TCP tunnel)
 *   - No authentication (0x00)
 *   - IPv4 and DOMAIN address types
 *
 * Not supported:
 *   - BIND and UDP ASSOCIATE commands
 *   - Username/password auth (0x02)
 *   - IPv6 addresses
 */
#ifndef SOCKS5_H
#define SOCKS5_H

#include <stddef.h>
#include <stdint.h>

/*
 * Handle a SOCKS5 handshake and return the target address.
 *
 *   client_fd:  socket connected to the SOCKS5 client (e.g., curl, browser)
 *   host:       [out] buffer for target hostname/IP (≥256 bytes)
 *   host_len:   [out] length of host string
 *   port:       [out] target TCP port (network byte order → host order)
 *
 * Returns 0 on success (CONNECT granted, fd ready for data).
 * Returns -1 on protocol error or unsupported command.
 *
 * After successful return, client_fd is in data-transfer mode:
 * all subsequent reads/writes are tunneled to the target.
 */
int socks5_accept(int client_fd,
                  char *host, size_t *host_len, uint16_t *port);

#endif /* SOCKS5_H */
