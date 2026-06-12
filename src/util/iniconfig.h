/*
 * iniconfig.h — WireGuard-style INI configuration file parser
 *
 * Format:
 *   [Interface]
 *   PrivateKey = /home/user/.aegis-tunnel/private.key
 *   Address = 10.0.0.1/24
 *   Port = 9000
 *   Mode = server
 *
 *   [Peer]
 *   PublicKey = a1b2c3d4...
 *   Endpoint = server.com:9000
 *   AllowedIPs = 10.0.0.0/24
 *
 *   [Tunnel]
 *   Keepalive = 30
 *   MaxConnections = 64
 *
 * Usage:
 *   iniconf_t cfg;
 *   iniconf_load(&cfg, "/etc/aegis/aegis.conf");
 *   const char *key = iniconf_get(&cfg, "Interface", "Address");
 *   iniconf_free(&cfg);
 */
#ifndef INICONFIG_H
#define INICONFIG_H

#include <stddef.h>

#define INI_MAX_LINE    512
#define INI_MAX_SECTIONS  8
#define INI_MAX_KEYS     32

typedef struct {
    char *key;
    char *value;
} ini_entry_t;

typedef struct {
    char *name;
    ini_entry_t entries[INI_MAX_KEYS];
    size_t count;
} ini_section_t;

typedef struct {
    ini_section_t sections[INI_MAX_SECTIONS];
    size_t count;
} iniconf_t;

/* Load INI config file. Returns 0 on success, -1 on error. */
int  iniconf_load(iniconf_t *cfg, const char *path);

/* Get value from first matching section. Returns NULL if not found. */
const char *iniconf_get(const iniconf_t *cfg, const char *section, const char *key);

/* Get value from the n-th occurrence of a section (0-based index).
 * Use when multiple same-named sections exist (e.g. [Peer] [Peer] ...).
 * Returns NULL if section/key not found at that index. */
const char *iniconf_get_indexed(const iniconf_t *cfg, const char *section,
                                 int index, const char *key);

/* Get integer value (returns default_val if not found). */
int  iniconf_get_int(const iniconf_t *cfg, const char *section, const char *key, int default_val);

/* Free all memory. */
void iniconf_free(iniconf_t *cfg);

#endif /* INICONFIG_H */
