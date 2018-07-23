#ifndef __SYS_PLATFORM_H__
#define __SYS_PLATFORM_H__

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <math.h>

//#include <link.h>

#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

#ifndef RTLD_NOLOAD
#define RTLD_NOLOAD 0
#endif

#define SHLIB_EX           "so"
#define HAVE_STRING_H
#define posix_clock_gettime clock_gettime

#ifndef gmtime_s
#define gmtime_s(a,b) gmtime_r(b,a)
#endif

#ifndef alloca
#define alloca(size) __builtin_alloca(size)
#endif

#ifndef WEXITSTATUS
#define WEXITSTATUS(status) 0
#endif

#ifdef CONFIG_ARM
struct dl_phdr_info;
static inline int 
dl_iterate_phdr(int (*cb)(struct dl_phdr_info*, size_t len, void*u), void*usr) 
{
	return -1;
}
#endif

const char *
get_process_file(void);
/*
#include <sys/syscall.h>
#ifdef SYS_gettid
static inline pid_t gettid(void)
{
	return syscall(SYS_gettid);
}
#else
#error "SYS_gettid unavailable on this system"
#endif
*/
char **setproctitle_init(int argc, char *argv[]);
void setproctitle(const char *fmt, ...);

ssize_t
getdelim(char **buf, size_t *bufsiz, int delimiter, FILE *fp);
ssize_t
getline(char **buf, size_t *bufsiz, FILE *fp);

#ifndef log2
#define log2(x) (log(x) / log(2.0))
#endif

#endif
