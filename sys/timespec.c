#include <sys/compiler.h>
#include <sys/log.h>
#include <sys/time.h>
#include <time.h>
#include <stdio.h>

void
timespec_now(struct timespec *ts)
{
	struct timeval  tv;
	gettimeofday(&tv, NULL);
	ts->tv_sec  = tv.tv_sec;
	ts->tv_nsec = tv.tv_usec * 1000;  
}

void
timespec_add_ms(struct timespec *ts, long ms)
{
	int sec=ms / 1000;
	ms=ms-sec * 1000;
	ts->tv_nsec+=ms * 1000000;
	ts->tv_sec+=ts->tv_nsec / 1000000000 + sec;
	ts->tv_nsec=ts->tv_nsec % 1000000000;
}

void
timespec_add_ns(struct timespec *ts, long ns)
{
	int sec = ns / 1000000000;
	ns=ns - sec * 1000000000;
	ts->tv_nsec += ns;
	ts->tv_sec  += ts->tv_nsec / 1000000000 + sec;
	ts->tv_nsec  = ts->tv_nsec % 1000000000;
}

void
timeval_set(struct timeval *tv, double d)
{
	long l = d * 1000000;
	tv->tv_sec = l / 1000000;
	tv->tv_usec = l - tv->tv_sec * 1000000;
}

void
timespec_adj(struct timespec *ts, double d)
{
	long sec = (int)d;
	long ns = (d - sec) * 1000000000;

	while (ns < 0) {
		ns += 1000000000;
		sec--;
	}

	ts->tv_nsec += ns;
	ts->tv_sec  += ts->tv_nsec / 1000000000 + sec;
	ts->tv_nsec  = ts->tv_nsec % 1000000000;
}

int
timespec_cmp(struct timespec *a, struct timespec *b)
{
	if (a->tv_sec!=b->tv_sec)
		return a->tv_sec-b->tv_sec;

	return a->tv_nsec-b->tv_nsec;
}

void
timespec_sub(struct timespec *a, struct timespec *b)
{
	a->tv_nsec = a->tv_nsec - b->tv_nsec;
	if (a->tv_nsec < 0) {
		a->tv_nsec += 1000000000;
		a->tv_sec--;
	}

	a->tv_sec = a->tv_sec - b->tv_sec;
}

int
timespec_milliseconds(struct timespec *ts) 
{
	return ts->tv_sec * 1000 + ts->tv_nsec / 1000000;
}

void
timespec_show(struct timespec *ts)
{
	info("%jd.%09jd", (intmax_t)ts->tv_sec, (intmax_t)ts->tv_nsec);
}
