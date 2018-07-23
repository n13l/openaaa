#include <sys/compiler.h>
#include <sys/log.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#include <unix/timespec.h>

#ifndef CLOCK_REALTIME
#define CLOCK_REALTIME 1
#endif


#ifndef CONFIG_ARM

timestamp_t
get_timestamp(void)
{
	struct timespec ts;
	if (posix_clock_gettime(CLOCK_REALTIME, &ts))
		exit(1);
	return ((timestamp_t) ts.tv_sec) * 1000000000LLU 
	      +((timestamp_t) ts.tv_nsec);
}

#else

timestamp_t
get_timestamp(void)
{
        return 0;
}	

#endif
