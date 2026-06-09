/*
 * config.c — Key=value config parser implementation
 */
#include "util/config.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int config_load(config_t *cfg, const char *path)
{
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;

    memset(cfg, 0, sizeof(*cfg));
    char line[CONFIG_MAX_LINE];

    while (fgets(line, sizeof(line), fp) && cfg->count < CONFIG_MAX_ENTRIES) {
        /* Trim trailing whitespace and newline */
        char *end = line + strlen(line);
        while (end > line && isspace((unsigned char)*(end - 1)))
            *--end = '\0';
        if (*line == '\0') continue;

        /* Skip comments */
        char *start = line;
        while (isspace((unsigned char)*start)) start++;
        if (*start == '#' || *start == '\0') continue;

        /* Find '=' separator */
        char *eq = strchr(start, '=');
        if (!eq) continue;

        /* Extract key (trim right whitespace) */
        char *key_end = eq;
        while (key_end > start && isspace((unsigned char)*(key_end - 1)))
            key_end--;
        *key_end = '\0';

        /* Extract value (trim left whitespace) */
        char *val = eq + 1;
        while (isspace((unsigned char)*val)) val++;

        cfg->entries[cfg->count].key   = strdup(start);
        cfg->entries[cfg->count].value = strdup(val);
        cfg->count++;
    }

    fclose(fp);
    return 0;
}

const char *config_get(const config_t *cfg, const char *key)
{
    for (size_t i = 0; i < cfg->count; i++) {
        if (strcmp(cfg->entries[i].key, key) == 0)
            return cfg->entries[i].value;
    }
    return NULL;
}

int config_get_int(const config_t *cfg, const char *key, int default_val)
{
    const char *val = config_get(cfg, key);
    if (!val) return default_val;
    char *end = NULL;
    long n = strtol(val, &end, 10);
    if (end == val || *end != '\0') return default_val;
    return (int)n;
}

void config_free(config_t *cfg)
{
    for (size_t i = 0; i < cfg->count; i++) {
        free(cfg->entries[i].key);
        free(cfg->entries[i].value);
    }
    memset(cfg, 0, sizeof(*cfg));
}
