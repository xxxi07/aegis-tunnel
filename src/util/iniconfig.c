/*
 * iniconfig.c — WireGuard-style INI config parser
 */
#include "util/iniconfig.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int iniconf_load(iniconf_t *cfg, const char *path)
{
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;

    memset(cfg, 0, sizeof(*cfg));
    char line[INI_MAX_LINE];
    ini_section_t *sec = NULL;

    while (fgets(line, sizeof(line), fp) && cfg->count < INI_MAX_SECTIONS) {
        /* Trim trailing whitespace */
        char *end = line + strlen(line);
        while (end > line && isspace((unsigned char)*(end - 1))) *--end = '\0';
        if (*line == '\0') continue;

        /* Find start of content */
        char *p = line;
        while (isspace((unsigned char)*p)) p++;
        if (*p == '#' || *p == ';' || *p == '\0') continue;

        /* Section header: [Section] */
        if (*p == '[') {
            char *close = strchr(p + 1, ']');
            if (close) {
                *close = '\0';
                sec = &cfg->sections[cfg->count];
                sec->name = strdup(p + 1);
                sec->count = 0;
                cfg->count++;
                *close = ']';
            }
            continue;
        }

        /* Key = Value (only inside a section) */
        if (!sec) continue;
        char *eq = strchr(p, '=');
        if (!eq) continue;
        if (sec->count >= INI_MAX_KEYS) continue;

        /* Extract key (trim right whitespace) */
        char *kend = eq;
        while (kend > p && isspace((unsigned char)*(kend - 1))) kend--;
        *kend = '\0';

        /* Extract value (trim left whitespace) */
        char *val = eq + 1;
        while (isspace((unsigned char)*val)) val++;

        sec->entries[sec->count].key   = strdup(p);
        sec->entries[sec->count].value = strdup(val);
        sec->count++;
    }

    fclose(fp);
    return 0;
}

const char *iniconf_get(const iniconf_t *cfg, const char *section, const char *key)
{
    for (size_t s = 0; s < cfg->count; s++) {
        if (strcasecmp(cfg->sections[s].name, section) == 0) {
            for (size_t i = 0; i < cfg->sections[s].count; i++) {
                if (strcasecmp(cfg->sections[s].entries[i].key, key) == 0)
                    return cfg->sections[s].entries[i].value;
            }
            return NULL;  /* section found but key not found */
        }
    }
    return NULL;
}

const char *iniconf_get_indexed(const iniconf_t *cfg, const char *section,
                                 int index, const char *key)
{
    int nth = 0;
    for (size_t s = 0; s < cfg->count; s++) {
        if (strcasecmp(cfg->sections[s].name, section) == 0) {
            if (nth == index) {
                for (size_t i = 0; i < cfg->sections[s].count; i++) {
                    if (strcasecmp(cfg->sections[s].entries[i].key, key) == 0)
                        return cfg->sections[s].entries[i].value;
                }
                return NULL;
            }
            nth++;
        }
    }
    return NULL;
}

int iniconf_get_int(const iniconf_t *cfg, const char *section, const char *key, int def)
{
    const char *v = iniconf_get(cfg, section, key);
    if (!v) return def;
    char *end = NULL;
    long n = strtol(v, &end, 10);
    return (end != v && *end == '\0') ? (int)n : def;
}

void iniconf_free(iniconf_t *cfg)
{
    for (size_t s = 0; s < cfg->count; s++) {
        free(cfg->sections[s].name);
        for (size_t i = 0; i < cfg->sections[s].count; i++) {
            free(cfg->sections[s].entries[i].key);
            free(cfg->sections[s].entries[i].value);
        }
    }
    memset(cfg, 0, sizeof(*cfg));
}
