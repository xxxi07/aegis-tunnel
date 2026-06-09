/*
 * log.h — Simple leveled logging with timestamps
 *
 * Four log levels: ERROR, WARN, INFO, DEBUG
 * Output goes to stderr with [timestamp] [level] prefix.
 *
 * Usage:
 *   log_set_level(LOG_INFO);          // suppress DEBUG messages
 *   log_info("server", "listening on port %d", port);
 *   log_error("handshake", "auth failed: %s", reason);
 */
#ifndef LOG_H
#define LOG_H

typedef enum {
    LOG_DEBUG = 0,
    LOG_INFO  = 1,
    LOG_WARN  = 2,
    LOG_ERROR = 3,
    LOG_NONE  = 4,
} log_level_t;

/* Set minimum log level (messages below this are suppressed) */
void log_set_level(log_level_t level);

/* Get current log level */
log_level_t log_get_level(void);

/* Log functions */
void log_debug(const char *tag, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
void log_info (const char *tag, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
void log_warn (const char *tag, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
void log_error(const char *tag, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

#endif /* LOG_H */
