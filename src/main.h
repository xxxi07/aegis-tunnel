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
#define MAX_PEERS 16

extern int  g_asym_mode;
extern int  g_tun_multipath;   /* number of parallel TCP connections */
extern uint8_t g_asym_priv[32];
extern uint8_t g_asym_peers[MAX_PEERS][32];
extern char   g_peer_endpoints[MAX_PEERS][256];
extern uint32_t g_peer_tun_ips[MAX_PEERS];  /* TUN IP for each peer (network byte order) */
extern int  g_peer_count;

/* ── Utility ── */
int  read_psk_file(uint8_t *psk, size_t max_len, const char *path);
int  parse_hex(uint8_t *out, size_t out_max, const char *hex);
int  parse_host_port(char *addr_str, char **host, int *port);
int  connect_to_host(const char *host, int port, int fwmark);
int  connect_to_host_mptcp(const char *host, int port, int fwmark);
int  listen_on_port(int port);
int  listen_on_port_mptcp(int port);

/* ── Mode functions ── */
int mode_psk_server(int listen_port, const char *remote_host, int remote_port,
                    const uint8_t *psk, size_t psk_len, int hs_timeout, int keepalive);
int mode_psk_client(int listen_port, const char *remote_host, int remote_port,
                    const uint8_t *psk, size_t psk_len, int hs_timeout, int keepalive);
int mode_tun_server(int listen_port, const char *tun_name,
                    const char *tun_ip, const char *tun_netmask, const char *tun_route,
                    const char *tun_nat_if,
                    const char *postup, const char *postdown,
                    const uint8_t *psk, size_t psk_len, int hs_timeout, int keepalive);
int mode_tun_client(int listen_port, const char *remote_host, int remote_port,
                    const char *tun_name,
                    const char *tun_ip, const char *tun_netmask, const char *tun_route,
                    const char *postup, const char *postdown,
                    const uint8_t *psk, size_t psk_len, int hs_timeout, int keepalive);

/* ── SOCKS5 proxy modes ── */
int mode_socks5_server(int listen_port,
                       const uint8_t *psk, size_t psk_len,
                       int hs_timeout, int keepalive);
int mode_socks5_client(const char *remote_host, int remote_port,
                       int listen_port,
                       const uint8_t *psk, size_t psk_len,
                       int hs_timeout, int keepalive);

/* ── TUN UDP transport modes ── */
int mode_tun_udp_server(int listen_port,
                         const char *tun_name,
                         const char *tun_ip, const char *tun_netmask,
                         const char *tun_route, const char *tun_nat_if,
                         const char *postup, const char *postdown,
                         const uint8_t *psk, size_t psk_len,
                         int hs_timeout, int keepalive);
int mode_tun_udp_client(const char *remote_host, int remote_port,
                         const char *tun_name,
                         const char *tun_ip, const char *tun_netmask,
                         const char *tun_route,
                         const char *postup, const char *postdown,
                         const uint8_t *psk, size_t psk_len,
                         int hs_timeout, int keepalive);

#endif /* MAIN_H */


