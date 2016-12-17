#ifndef __SYS_LOG_H__
#define __SYS_LOG_H__

#include <sys/compiler.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <errno.h>
#include <time.h>
#include <unix/timespec.h>

#ifndef CLOCK_REALTIME
#define CLOCK_REALTIME 1
#endif

#ifndef KBUILD_BASENAME
#define KBUILD_BASENAME "test"
#endif

#ifndef KBUILD_MODNAME
#define KBUILD_MODNAME "test"
#endif

#ifdef CONFIG_LOGGING
# ifdef CONFIG_LOGGING_TIME
#  define log_timespec \
	char __tss[100]; _unused struct tm __tm; struct timespec ts; \
	time_t __tmt = time(NULL); \
	gmtime_r(&__tmt, &__tm); \
	posix_clock_gettime(CLOCK_REALTIME, &ts); \
	strftime(__tss, sizeof(__tss) - 1, "%m/%d/%Y %H:%M:%S", &__tm);
#  define log_time_fmt "%s.%09ld %-6s "
#  define log_time_arg __tss, ts.tv_nsec, KBUILD_MODNAME ":"
# endif
#endif

#ifndef log_time_fmt
#define log_time_fmt "%s"
#endif

#ifndef log_time_arg
#define log_time_arg ""
#endif

#ifndef log_timespec
#define log_timespec do {} while(0);
#endif

#define log_fmt(fmt) log_time_fmt fmt "\n"
#define log_arg log_time_arg

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

#define sys_dbg(fmt, ...) \
	printf(fmt "\n", ## __VA_ARGS__)
#define sys_info(fmt, ...) \
	printf(fmt "\n", ## __VA_ARGS__)
#define sys_msg(fmt, ...) \
	printf(fmt "\n", ## __VA_ARGS__)
#define sys_err(fmt, ...) \
	printf(fmt "\n", ## __VA_ARGS__)

/*
do { \
	log_timespec \
	printf(log_fmt(fmt), log_arg,## __VA_ARGS__); \
} while(0)
*/

#ifdef CONFIG_LOGGING
#define debug(fmt, ...) \
do { \
	printf(fmt "\n", ## __VA_ARGS__); \
} while(0)

#define info(fmt, ...) \
do { \
	printf(fmt "\n", ## __VA_ARGS__); \
} while(0)

#define error(fmt, ...)
#define warning(fmt, ...)
#else
#define debug(fmt, ...) do { } while(0)
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

#endif
