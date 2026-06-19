/*
 * mode_common.c — Shared code between mode_psk.c and mode_tun.c
 */
#include "mode_common.h"
#include "main.h"
#include "util/log.h"

#include <arpa/inet.h>
#include <string.h>
#include <time.h>

/* ─── Per-IP handshake rate limiter (anti-DoS) ─────────────────── */

#define RATE_MAX_IPS     32      /* tracked IP slots */
#define RATE_MAX_ATTEMPTS  5      /* max handshake attempts per window */
#define RATE_WINDOW_SEC   60      /* sliding window */

typedef struct {
    char  ip[INET_ADDRSTRLEN];
    int   count;
    int64_t window_start;
} rate_entry_t;

static rate_entry_t rate_table[RATE_MAX_IPS];
static size_t       rate_next_slot = 0;

int handshake_rate_check(const char *ip, int64_t now)
{
    /* Look for existing entry */
    for (int i = 0; i < RATE_MAX_IPS; i++) {
        if (rate_table[i].ip[0] && !strcmp(rate_table[i].ip, ip)) {
            /* Reset window if expired */
            if (now - rate_table[i].window_start > RATE_WINDOW_SEC) {
                rate_table[i].count        = 1;
                rate_table[i].window_start = now;
                return 0;
            }
            /* Within window: check limit */
            if (++rate_table[i].count > RATE_MAX_ATTEMPTS) {
                log_warn("rate-limit", "%s: %d handshakes in %llds — blocked",
                         ip, rate_table[i].count,
                         (long long)(now - rate_table[i].window_start));
                return -1;
            }
            return 0;
        }
    }

    /* New IP — take next slot (round-robin eviction) */
    rate_entry_t *e = &rate_table[rate_next_slot];
    rate_next_slot  = (rate_next_slot + 1) % RATE_MAX_IPS;
    strncpy(e->ip, ip, sizeof(e->ip) - 1);
    e->ip[sizeof(e->ip) - 1] = '\0';
    e->count         = 1;
    e->window_start  = now;
    return 0;
}

/* ─── Multi-peer handshake ─────────────────────────────────────── */

int try_handshake_server(int fd, session_keys_t *keys, int timeout_ms)
{
    for (int i = 0; i < g_peer_count; i++) {
        if (handshake_server(fd, g_asym_priv, g_asym_peers[i], timeout_ms, keys) == 0) {
            log_info("server", "peer #%d authenticated", i);
            return i;  /* return peer index, not just 0 */
        }
    }
    return -1;
}
