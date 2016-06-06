#ifndef __SYS_LOG_H__
#define __SYS_LOG_H__

#include <sys/compiler.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <errno.h>

#define __syscall_error(fn, args)                                             \
do {                                                                          \
	printf("%s: %s %s %s\n", __func__, fn, args, strerror(errno));   \
} while(0)

static inline bool syscall_voidp(void *arg) { return arg ? false: true;}
static inline bool syscall_filep(FILE *arg) { return arg ? false: true;}
static inline bool syscall_int  (int arg)   { return arg >= 0 ? false: true;}
static inline bool syscall_lint (long int arg){ return arg >= 0 ? false: true;}

/*
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

*/

#define sys_dbg(fmt, ...) \
	printf(fmt "\n", ## __VA_ARGS__)
#define sys_info(fmt, ...) \
	printf(fmt "\n", ## __VA_ARGS__)
#define sys_msg(fmt, ...) \
	printf(fmt "\n", ## __VA_ARGS__)
#define sys_err(fmt, ...) \
	printf(fmt "\n", ## __VA_ARGS__)

void
die(const char *fmt, ...);
                                                                                
void
vdie(const char *fmt, va_list args);
                                                                                
void                                                                  
giveup(const char *fmt, ...);

#endif
