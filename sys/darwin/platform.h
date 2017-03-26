#ifndef __SYS_PLATFORM_H__
#define __SYS_PLATFORM_H__

#define SHLIB_EX           "dylib"

#define HAVE_STRING_H

int
mremap(void *addr, int size , int , int);

#ifndef CLOCK_REALTIME
#define CLOCK_REALTIME 1
#endif

#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC 2
#endif

#ifndef gmtime_s
#define gmtime_s(a,b) gmtime_r(b,a)
#endif

struct timespec;

#ifndef gettid
#define gettid(...) (int)1
#endif

int
posix_clock_gettime(int clock_id, struct timespec *ts);

#endif
