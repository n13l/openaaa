#ifndef __SYS_LOG_H__
#define __SYS_LOG_H__

#include <sys/compiler.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <errno.h>
#include <time.h>

#ifndef LOG_ERROR
#define LOG_ERROR 1
#endif

#ifndef LOG_INFO
#define LOG_INFO 2
#endif

#ifndef LOG_WARN
#define LOG_WARN 3
#endif

#ifndef LOG_DEBUG
#define LOG_DEBUG 4
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
  if (log_verbose < 0) break; \
  struct log_ctx log_ctx = { .module = KBUILD_MODNAME, .fn = __func__ }; \
  log_printf(&log_ctx, log_fmt(fmt), ## __VA_ARGS__); \
} while(0)

#define debug1(fmt, ...) \
do { \
  if (log_verbose < 1) break; \
  struct log_ctx log_ctx = { .module = KBUILD_MODNAME, .fn = __func__ }; \
  log_printf(&log_ctx, log_fmt(fmt), ## __VA_ARGS__); \
} while(0)

#define debug2(fmt, ...) \
do { \
  if (log_verbose < 2) break; \
  struct log_ctx log_ctx = { .module = KBUILD_MODNAME, .fn = __func__ }; \
  log_printf(&log_ctx, fmt, ## __VA_ARGS__); \
} while(0)

/* printf("%s:%s(): " fmt "\n", KBUILD_MODNAME, __func__,  ## __VA_ARGS__); */

#define debug3(fmt, ...) \
do { \
  if (log_verbose < 3) break; \
  struct log_ctx log_ctx = { .module = KBUILD_MODNAME, .fn = __func__ }; \
  log_printf(&log_ctx, log_fmt(fmt), ## __VA_ARGS__); \
} while(0)

#define debug4(fmt, ...) \
do { \
  if (log_verbose < 4) break; \
  struct log_ctx log_ctx = { .module = KBUILD_MODNAME, .fn = __func__ }; \
  log_printf(&log_ctx, log_fmt(fmt), ## __VA_ARGS__); \
} while(0)

#define info(fmt, ...) \
do { \
  struct log_ctx log_ctx = { .module = KBUILD_MODNAME, .fn = __func__ }; \
  log_printf(&log_ctx, log_fmt(fmt), ## __VA_ARGS__); \
} while(0)

#define error(fmt, ...) \
do { \
  struct log_ctx log_ctx = { .module = KBUILD_MODNAME, .fn = __func__ }; \
  log_printf(&log_ctx, log_fmt(fmt), ## __VA_ARGS__); \
} while(0)

#define warning(fmt, ...) \
do { \
  struct log_ctx log_ctx = { .module = KBUILD_MODNAME, .fn = __func__ }; \
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
log_open(void);

void
log_close(void);

typedef void (*log_write_fn)(struct log_ctx *, const char *, int );

void
log_custom_set(log_write_fn fn, void *user);

void
log_vprintf(struct log_ctx *ctx, const char *fmt, va_list args);

void
log_printf(struct log_ctx *ctx, const char *fmt, ...) 
           __attribute__ ((__format__ (__printf__, 2, 3)));

#endif
