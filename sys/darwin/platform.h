#ifndef __SYS_PLATFORM_H__
#define __SYS_PLATFORM_H__

#include <sys/compiler.h>
#include <sys/time.h>

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

struct mach_header;

struct dl_phdr_info {
	void *dlpi_addr;
	const char *dlpi_name;
	const struct mach_header *dlpi_phdr;
	u64 dlpi_phnum;
};

int
dl_iterate_phdr(int (*cb) (struct dl_phdr_info *info, 
                size_t size, void *data), void *data);


#endif
