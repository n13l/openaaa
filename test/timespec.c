#include <stdio.h>
#include <time.h>

#define TIME_UTC 0
/* C11 timespec_get */
int
main(void)
{
	struct timespec ts;
	timespec_get(&ts, TIME_UTC);
	char buff[100];
	strftime(buff, sizeof buff, "%D %T", gmtime(&ts.tv_sec));
	printf("Current time: %s.%09ld UTC\n", buff, ts.tv_nsec);
}
