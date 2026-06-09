/*
 * config.h — Simple key=value configuration file parser
 *
 * Format (one key=value per line, # comments, blank lines ignored):
 *   # Server config
 *   LISTEN_PORT = 9000
 *   REMOTE_ADDR = 127.0.0.1:8080
 *   MODE = server
 *   MAX_CONNS = 64
 *   KEEPALIVE = 30
 *
 * Usage:
 *   config_t cfg;
 *   config_load(&cfg, "/etc/aegis/server.conf");
 *   const char *val = config_get(&cfg, "LISTEN_PORT");
 *   int port = config_get_int(&cfg, "LISTEN_PORT", 9000);
 *   config_free(&cfg);
 */
#ifndef CONFIG_H
#define CONFIG_H

#include <stddef.h>

#define CONFIG_MAX_LINE    512
#define CONFIG_MAX_ENTRIES 64

typedef struct {
    char *key;
    char *value;
} config_entry_t;

typedef struct {
    config_entry_t entries[CONFIG_MAX_ENTRIES];
    size_t count;
} config_t;

/* Load config from file. Returns 0 on success, -1 on error. */
int  config_load(config_t *cfg, const char *path);

/* Get string value (NULL if not found) */
const char *config_get(const config_t *cfg, const char *key);

/* Get integer value (returns default_val if not found or unparseable) */
int  config_get_int(const config_t *cfg, const char *key, int default_val);

/* Free all allocated memory */
void config_free(config_t *cfg);

#endif /* CONFIG_H */
