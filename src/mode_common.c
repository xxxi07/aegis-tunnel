/*
 * mode_common.c — Shared code between mode_psk.c and mode_tun.c
 */
#include "mode_common.h"
#include "main.h"
#include "util/log.h"

int try_handshake_server(int fd, session_keys_t *keys, int timeout_ms)
{
    for (int i = 0; i < g_peer_count; i++) {
        if (handshake_server(fd, g_asym_priv, g_asym_peers[i], timeout_ms, keys) == 0) {
            log_info("server", "peer #%d authenticated", i);
            return 0;
        }
    }
    return -1;
}
