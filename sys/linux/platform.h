#ifndef __SYS_PLATFORM_H__
#define __SYS_PLATFORM_H__

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>

#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

#define SHLIB_EX           "so"
#define HAVE_STRING_H
#define posix_clock_gettime clock_gettime

#ifndef gmtime_s
#define gmtime_s(a,b) gmtime_r(b,a)
#endif

const char *
get_process_file(void);

#include <sys/syscall.h>
#ifdef SYS_gettid
static inline pid_t gettid(void)
{
	return syscall(SYS_gettid);
}
#else
#error "SYS_gettid unavailable on this system"
#endif

void setproctitle_init(int argc, char *argv[]);
void setproctitle(const char *fmt, ...);

#endif
