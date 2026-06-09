/*
 * log.c — Leveled logging implementation
 */
#include "util/log.h"

#include <stdarg.h>
#include <stdio.h>
#include <time.h>

static log_level_t g_log_level = LOG_INFO;

static const char *level_names[] = {
    [LOG_DEBUG] = "DEBUG",
    [LOG_INFO]  = "INFO",
    [LOG_WARN]  = "WARN",
    [LOG_ERROR] = "ERROR",
};

void log_set_level(log_level_t level) { g_log_level = level; }
log_level_t log_get_level(void)         { return g_log_level; }

static void log_msg(log_level_t level, const char *tag,
                    const char *fmt, va_list ap)
{
    if (level < g_log_level) return;

    /* Timestamp */
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm;
    localtime_r(&ts.tv_sec, &tm);

    fprintf(stderr, "[%02d:%02d:%02d.%03ld] [%-5s] [%s] ",
            tm.tm_hour, tm.tm_min, tm.tm_sec,
            ts.tv_nsec / 1000000,
            level_names[level], tag);

    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    fflush(stderr);
}

void log_debug(const char *tag, const char *fmt, ...) {
    va_list ap; va_start(ap, fmt); log_msg(LOG_DEBUG, tag, fmt, ap); va_end(ap);
}
void log_info(const char *tag, const char *fmt, ...) {
    va_list ap; va_start(ap, fmt); log_msg(LOG_INFO, tag, fmt, ap); va_end(ap);
}
void log_warn(const char *tag, const char *fmt, ...) {
    va_list ap; va_start(ap, fmt); log_msg(LOG_WARN, tag, fmt, ap); va_end(ap);
}
void log_error(const char *tag, const char *fmt, ...) {
    va_list ap; va_start(ap, fmt); log_msg(LOG_ERROR, tag, fmt, ap); va_end(ap);
}
