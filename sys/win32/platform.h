#ifndef __SYS_PLATFORM_H__
#define __SYS_PLATFORM_H__

#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#ifndef RTLD_NOLOAD
#define RTLD_NOLOAD 0
#endif

#define SHLIB_EX           "dll"

#define HAVE_STRING_H

#define F_LOCK  1
#define F_ULOCK 0
#define F_TLOCK 2
#define F_TEST  3

#define F_GETFL 4

#if defined(__MINGW32__) || defined(__MINGW64__) 

#define WIFEXITED(x) ((x) != 3)
#define WEXITSTATUS(x) (x)

#ifndef S_ISLNK
#define S_ISLNK(X) 0
#endif

#ifndef lstat
#define lstat stat
#endif

#ifndef readlink
#define readlink(file, path, size) do {} while(0)
#endif

int
fsync(int fd);

int
fcntl(int fd, int cmd, ... /* arg */ );

#else

#endif

/*
#ifndef gmtime_r
#define gmtime_r(a,b) gmtime_s(b,a)
#endif
*/
#ifndef gettid
#define gettid(...) 0
//#define gettid(...) (int)GetCurrentThreadId()
#endif

#ifndef getpid
#define getpid _getpid
#endif

#define sleep(a) Sleep(a * 1000)

int
setenv(const char *name, const char *value, int overwrite);

struct tm *
gmtime_r(const time_t *timep, struct tm *result);

struct timespec;

char *
strsignal(int sig);

int
posix_clock_gettime(int id, struct timespec *tv);

void win32_stacktrace(void *ctx);

#include <sys/win32/sigbits.h>

#endif
