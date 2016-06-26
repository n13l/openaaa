#include <sys/compiler.h>
#include <sys/log.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#include <posix/timespec.h>

#ifndef CLOCK_REALTIME
#define CLOCK_REALTIME 1
#endif

timestamp_t
get_timestamp(void)
{
	struct timespec ts;
	if (posix_clock_gettime(CLOCK_REALTIME, &ts))
		exit(1);
	return ((timestamp_t) ts.tv_sec) * 1000000000LLU 
	      +((timestamp_t) ts.tv_nsec);
}
