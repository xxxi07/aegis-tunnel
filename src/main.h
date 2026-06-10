/*
 * main.h — Shared state between main.c and mode_*.c
 */
#ifndef MAIN_H
#define MAIN_H

#include "protocol/handshake.h"
#include <signal.h>
#include <stddef.h>
#include <stdint.h>

/* ── Globals shared across mode files ── */
extern volatile sig_atomic_t g_running;
extern volatile sig_atomic_t g_active_conns;
extern int  g_max_conns;
extern int  g_asym_mode;
extern uint8_t g_asym_priv[32];
extern uint8_t g_asym_peer[32];

/* ── Utility ── */
int  read_psk_file(uint8_t *psk, size_t max_len, const char *path);
int  parse_hex(uint8_t *out, size_t out_max, const char *hex);
int  parse_host_port(char *addr_str, char **host, int *port);
int  connect_to_host(const char *host, int port);
int  listen_on_port(int port);
void set_socket_timeout(int fd, int seconds);

/* ── Mode functions ── */
int mode_psk_server(int listen_port, const char *remote_host, int remote_port,
                    const uint8_t *psk, size_t psk_len, int hs_timeout, int keepalive);
int mode_psk_client(int listen_port, const char *remote_host, int remote_port,
                    const uint8_t *psk, size_t psk_len, int hs_timeout, int keepalive);
int mode_tun_server(int listen_port, const char *tun_name,
                    const char *tun_ip, const char *tun_netmask, const char *tun_route,
                    const char *tun_nat_if,
                    const uint8_t *psk, size_t psk_len, int hs_timeout, int keepalive);
int mode_tun_client(int listen_port, const char *remote_host, int remote_port,
                    const char *tun_name,
                    const char *tun_ip, const char *tun_netmask, const char *tun_route,
                    const uint8_t *psk, size_t psk_len, int hs_timeout, int keepalive);

#endif /* MAIN_H */

