#include <sys/compiler.h>
#include <stdint.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <time.h>
	
timestamp_t
darwin_gettimestamp(void)
{
	struct timespec tv;
	nanotime(&tv);
	return (tv.tv_sec * 10000000ULL) + 
	       (tv.tv_nsec / 100ULL) + 0x01B21DD213814000ULL;
}

