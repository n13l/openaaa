#ifndef __COMPAT_GETTID_H__
#define __COMPAT_GETTID_H__

#include <unistd.h>
#include <sys/syscall.h>
#ifdef SYS_gettid
static inline unsigned int compat_gettid(void)
{ 
	return (unsigned int) syscall(SYS_gettid);
}
#elif __APPLE__
#if TARGET_OS_IPHONE && TARGET_IPHONE_SIMULATOR
#elif TARGET_OS_IPHONE
#else
#define TARGET_OS_OSX 1
static inline unsigned int compat_gettid(void)
{
	return (unsigned int)pthread_self();
}
#endif
#else
#error "SYS_gettid unavailable on this system"
#endif

#endif
