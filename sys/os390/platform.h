#ifndef __SYS_PLATFORM_H__
#define __SYS_PLATFORM_H__

#include <sys/compiler.h>
#include <sys/xlc.h>

#define MAP_ANON MAP_ANONYMOUS
#define MAP_ANONYMOUS 0
#define MAP_FAILED -1

#ifndef CLOCK_REALTIME
#define CLOCK_REALTIME 1
#endif

#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC 2
#endif

#ifndef gmtime_s
#define gmtime_s(a,b) gmtime_r(b,a)
#endif

struct timespec {
	u64 tv_sec;
	u64 tv_nsec;
};

int
posix_clock_gettime(int clock_id, struct timespec *ts);

#endif
