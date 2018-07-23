#ifndef __SYS_LOG_H__
#define __SYS_LOG_H__

#include <sys/compiler.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <errno.h>
#include <time.h>
#ifndef CONFIG_ARM
#include <syslog.h>
#endif

#define LOG_CAP_LEVEL     1
#define LOG_CAP_TIME      2
#define LOG_CAP_TIMESTAMP 4
#define LOG_CAP_PID       8
#define LOG_CAP_TID       16 
#define LOG_CAP_USER      32
#define LOG_CAP_MODULE    64
#define LOG_CAP_FN        128

enum log_type_e {
	LOG_TYPE_SYSLOG = 1,
	LOG_TYPE_STDOUT = 2,
	LOG_TYPE_STDERR = 3,
	LOG_TYPE_FILE   = 4,
};

#ifndef LOG_USER
#define LOG_USER        (1<<3)  /* random user-level messages */
#endif
#ifndef LOG_DAEMON
#define LOG_DAEMON      (3<<3)  /* system daemons */
#endif
#ifndef LOG_AUTH
#define LOG_AUTH        (4<<3)  /* security/authorization messages */
#endif
#ifndef LOG_AUTHPRIV
#define LOG_AUTHPRIV    (10<<3) /* security/authorization messages (private) */ 
#endif

/*
 * https://tools.ietf.org/html/rfc5424
 *
 * TODO: asynchsafe syslog()
 *
 * logging code support for outputting syslog, just uses the regular C library 
 * syslog() function. The problem is that this function is not async signal safe, 
 * mostly because of its use of the printf family of functions internally. 
 * Annoyingly libvirt does not even need printf support here, because it has 
 * already expanded the log message string.
 *
 */

#ifndef LOG_ERROR
#define LOG_ERROR 3
#endif

#ifndef LOG_WARN
#define LOG_WARN 4
#endif

#ifndef LOG_INFO
#define LOG_INFO 6
#endif

#ifndef LOG_DEBUG
#define LOG_DEBUG 7
#endif
#ifndef LOG_DEBUG1
#define LOG_DEBUG1 8
#endif
#ifndef LOG_DEBUG2
#define LOG_DEBUG2 9
#endif
#ifndef LOG_DEBUG3
#define LOG_DEBUG3 10
#endif
#ifndef LOG_DEBUG4
#define LOG_DEBUG4 11
#endif

#ifndef CLOCK_REALTIME
#define CLOCK_REALTIME 1
#endif

#ifndef KBUILD_MODNAME
#define KBUILD_MODNAME ""
#endif

#define __syscall_error(fn, args)                                             \
do {                                                                          \
	printf("%s: %s %s %s\n", __func__, fn, args, strerror(errno));   \
} while(0)

static inline bool syscall_voidp(void *arg) { return arg ? false: true;}
static inline bool syscall_filep(FILE *arg) { return arg ? false: true;}
static inline bool syscall_int  (int arg)   { return arg >= 0 ? false: true;}
static inline bool syscall_lint (long int arg){ return arg >= 0 ? false: true;}

#define __syscall_die(fn, args...) \
({ \
	__typeof__(fn args) __v = fn args; \
 	if (unlikely(_generic((__v), int     : syscall_int, \
	                             long int: syscall_lint, \
	                             void *  : syscall_voidp, \
	                             FILE *  : syscall_filep)(__v))) \
		{ __syscall_error(#fn, #args); exit(errno);} \
	__v; \
})

extern int log_verbose;

struct log_ctx {
	const char *module;
	const char *fn;
	char *file;
	int   line;
	int   level;
	void *user;
};

#define log_fmt(f) f 

#ifdef CONFIG_LOGGING
#define debug(fmt, ...) \
do { \
  if (log_verbose < 1) break; \
  struct log_ctx log_ctx = { .module = KBUILD_MODNAME, .fn = __func__, .level = LOG_DEBUG}; \
  log_printf(&log_ctx, log_fmt(fmt), ## __VA_ARGS__); \
} while(0)

#define debug1(fmt, ...) \
do { \
  if (log_verbose < 1) break; \
  struct log_ctx log_ctx = { .module = KBUILD_MODNAME, .fn = __func__, .level = LOG_DEBUG1 }; \
  log_printf(&log_ctx, log_fmt(fmt), ## __VA_ARGS__); \
} while(0)

#define debug2(fmt, ...) \
do { \
  if (log_verbose < 2) break; \
  struct log_ctx log_ctx = { .module = KBUILD_MODNAME, .fn = __func__, .level = LOG_DEBUG2 }; \
  log_printf(&log_ctx, log_fmt(fmt), ## __VA_ARGS__); \
} while(0)

#define debug3(fmt, ...) \
do { \
  if (log_verbose < 3) break; \
  struct log_ctx log_ctx = { .module = KBUILD_MODNAME, .fn = __func__, .level = LOG_DEBUG3 }; \
  log_printf(&log_ctx, log_fmt(fmt), ## __VA_ARGS__); \
} while(0)

#define debug4(fmt, ...) \
do { \
  if (log_verbose < 4) break; \
  struct log_ctx log_ctx = { .module = KBUILD_MODNAME, .fn = __func__, .level = LOG_DEBUG4 }; \
  log_printf(&log_ctx, log_fmt(fmt), ## __VA_ARGS__); \
} while(0)

#define info(fmt, ...) \
do { \
  struct log_ctx log_ctx = { .module = KBUILD_MODNAME, .fn = __func__ , .level = LOG_INFO}; \
  log_printf(&log_ctx, log_fmt(fmt), ## __VA_ARGS__); \
} while(0)

#define error(fmt, ...) \
do { \
  struct log_ctx log_ctx = { .module = KBUILD_MODNAME, .fn = __func__ , .level = LOG_ERROR}; \
  log_printf(&log_ctx, log_fmt(fmt), ## __VA_ARGS__); \
} while(0)

#define warning(fmt, ...) \
do { \
  struct log_ctx log_ctx = { .module = KBUILD_MODNAME, .fn = __func__ , .level = LOG_WARN}; \
  log_printf(&log_ctx, log_fmt(fmt), ## __VA_ARGS__); \
} while(0)

#else
#define debug(fmt, ...) do { } while(0)
#define debug1(fmt, ...) do { } while(0)
#define debug2(fmt, ...) do { } while(0)
#define debug3(fmt, ...) do { } while(0)
#define debug4(fmt, ...) do { } while(0)
#define info(fmt, ...) do { } while(0)
#define error(fmt, ...) do { } while(0)
#define warning(fmt, ...) do { } while(0)
#endif

void
die(const char *fmt, ...);

void
die_with_exitcode(int exitcode, const char *fmt, ...);
                                                                                
void
vdie(const char *fmt, va_list args);
                                                                                
void                                                                  
giveup(const char *fmt, ...);

void
log_name(const char *name);

void
log_open(const char *file, int facility);

void
log_close(void);

void
log_setcaps(int caps);

int
log_getcaps(void);

typedef void (*log_write_fn)(struct log_ctx *, const char *, int );

void
log_custom_set(log_write_fn fn, void *user);

void
log_vprintf(struct log_ctx *ctx, const char *fmt, va_list args);

void
log_printf(struct log_ctx *ctx, const char *fmt, ...) 
           __attribute__ ((__format__ (__printf__, 2, 3)));

#endif
