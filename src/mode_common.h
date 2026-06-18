/*
 * mode_common.h — Shared code between mode_psk.c and mode_tun.c
 */
#ifndef MODE_COMMON_H
#define MODE_COMMON_H

#include "protocol/handshake.h"

/*
 * Try handshake with each known peer key.
 * Returns peer index (0..g_peer_count-1) on success, -1 if no key works.
 * On success, keys is filled with the session keys.
 * Like SSH authorized_keys: any known peer can connect.
 */
int try_handshake_server(int fd, session_keys_t *keys, int timeout_ms);

#endif /* MODE_COMMON_H */
