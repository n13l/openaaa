/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2013 Daniel Kubec <niel@rtfm.cz>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"),to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <mach/mach.h>
#include <mach/clock.h>
#include <mach/mach_time.h>
#include <time.h>
#include <errno.h>
//#include <posix/darwin/platform.h>

int
posix_clock_gettime(int clock_id, struct timespec *ts)
{
	mach_timespec_t mts;
	static clock_serv_t real_clock = 0;
	static clock_serv_t mono_clock = 0;

	switch (clock_id) {
	case CLOCK_REALTIME:
		if (real_clock == 0)
			host_get_clock_service(mach_host_self(), 
					       CALENDAR_CLOCK, &real_clock);
	
		clock_get_time(real_clock, &mts);
		ts->tv_sec = mts.tv_sec;
		ts->tv_nsec = mts.tv_nsec;
		return 0;
	case CLOCK_MONOTONIC:
		if (mono_clock == 0)
			host_get_clock_service(mach_host_self(), 
					       SYSTEM_CLOCK, &mono_clock);
		
		clock_get_time(mono_clock, &mts);
		ts->tv_sec = mts.tv_sec;
		ts->tv_nsec = mts.tv_nsec;
		return 0;
	default:
		errno = EINVAL;
	return -1;
	}
}
