#ifndef __SYS_PLATFORM_H__
#define __SYS_PLATFORM_H__

/* https://sourceforge.net/p/mingw-w64/wiki2/gnu%20printf/ */
/*
#ifndef __SWIG__
#define __USE_MINGW_ANSI_STDIO 1
#endif
*/
#include <time.h>
#include <sys/time.h>
#include <sys/timeb.h>
#include <errno.h>

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

#define LOCK_EX F_LOCK
#define LOCK_NB F_TLOCK

#define LOCK_UN F_ULOCK

#if defined(__MINGW32__) || defined(__MINGW64__) 

#ifndef WIFEXITED
#define WIFEXITED(x) ((x) != 3)
#endif
#ifndef WEXITSTATUS
#define WEXITSTATUS(x) (x)
#endif

#ifndef S_ISLNK
#define S_ISLNK(X) 0
#endif

#ifndef lstat
#define lstat stat
#endif

#ifndef readlink
#define readlink(file, path, size) do {} while(0)
#endif

#ifndef MSG_TRUNC
#define MSG_TRUNC 0
#endif

int
fsync(int fd);

int
fcntl(int fd, int cmd, ... /* arg */ );

int
flock(int fd, int cmd);

int
kill(int pid, int signo);

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

int
setenv(const char *name, const char *value, int overwrite);

/*
struct tm *
gmtime_r(const time_t *timep, struct tm *result);
*/
struct timespec;

char *
strsignal(int sig);

int
posix_clock_gettime(int id, struct timespec *tv);

void win32_stacktrace(void *ctx);

#include <sys/win32/sigbits.h>

#ifndef sleep
//void sleep(unsigned int mseconds);
#endif

static inline char **setproctitle_init(int argc, char *argv[]) {return argv; };
static inline void setproctitle(const char *fmt, ...) { };

#endif
