#include <windows.h>
#include <sys/time.h>

/* 
 * TODO: link runtime
 * VOID WINAPI GetSystemTimePreciseAsFileTime(LPFILETIME lpSystemTimeAsFileTime);
 * void WINAPI GetSystemTimeAsFileTime(LPFILETIME lpSystemTimeAsFileTime);
 */

// static ULARGE_INTEGER epoch;

/*
static ULARGE_INTEGER
xgetfiletime(void)
{
	ULARGE_INTEGER now;
	FILETIME now_ft;

	GetSystemTimePreciseAsFileTime(&now_ft);
	now.LowPart = now_ft.dwLowDateTime;
	now.HighPart = now_ft.dwHighDateTime;

	return now;
}
*/

int
posix_clock_gettime(int id, struct timespec *ts)
{
/*	
	if (id == CLOCK_MONOTONIC) {
*/	
		static LARGE_INTEGER freq;
		LARGE_INTEGER count;
		long long int ns;

		if (!freq.QuadPart) {
			QueryPerformanceFrequency(&freq);
		}
		QueryPerformanceCounter(&count);

		ns = (double) count.QuadPart / freq.QuadPart * 1000000000;

		ts->tv_sec = count.QuadPart / freq.QuadPart;
		ts->tv_nsec = ns % 1000000000;
/*		
	} else if (id == CLOCK_REALTIME) {
		ULARGE_INTEGER now = xgetfiletime();

		ts->tv_sec = (now.QuadPart - epoch.QuadPart) / 10000000;
		ts->tv_nsec = ((now.QuadPart - epoch.QuadPart) % 10000000)*100;
	} 
*/
	return 0;
}

