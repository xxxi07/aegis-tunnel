/*
 * mode_common.h — Shared code between mode_psk.c and mode_tun.c
 */
#ifndef MODE_COMMON_H
#define MODE_COMMON_H

#include "protocol/handshake.h"

/*
 * Try handshake with each known peer key.  Returns 0 on success
 * (keys filled), -1 if no peer key works.
 * Like SSH authorized_keys: any known peer can connect.
 */
int try_handshake_server(int fd, session_keys_t *keys, int timeout_ms);

#endif /* MODE_COMMON_H */
