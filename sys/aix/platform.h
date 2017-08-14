#ifndef __SYS_AIX_PLATFORM_H__
#define __SYS_AIX_PLATFORM_H__

#include <sys/compiler.h>

#ifndef RTLD_NOLOAD
#define RTLD_NOLOAD  0x02000
#endif

#define _ALL_SOURCE 1

/* _GNU_SOURCE extensions */
typedef struct {
	const char *dli_fname;
	void *dli_fbase;      
	const char *dli_sname;
	void *dli_saddr;      
} Dl_info;

struct dl_phdr_info {
	void *dlpi_addr;  
	const char *dlpi_name;
};

int
dladdr(void *addr, Dl_info *info);

static int
dl_iterate_phdr(int (*cb)(struct dl_phdr_info *, size_t size, void *ptr), void *ctx)
{
	return -1;
}


#define off64_t off_t
#define ushort u16

#ifndef gettid
#define gettid(...) 0
//#define gettid(...) (int)GetCurrentThreadId()
#endif

struct timespec {
        u64 tv_sec;
        u64 tv_nsec;
};

int
posix_clock_gettime(int clock_id, struct timespec *ts);


#endif
