#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

struct tm *
gmtime_r(const time_t *timep, struct tm *tm)
{
	struct tm *r;
	r = gmtime(timep);
	memcpy(tm, r, sizeof(*r));
	return tm;
}
