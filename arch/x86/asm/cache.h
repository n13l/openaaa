#ifndef __ARCH_CPU_CACHE_H__
#define __ARCH_CPU_CACHE_H__

#include <sys/compiler.h>
#include <sys/cpu.h>

#ifdef CONFIG_LINUX
/*
#include <linux/asm/cachectl.h>
# define cpu_icache_flush(addr, len) cacheflush(addr, len, ICACHE);
# define cpu_dcache_flush(addr, len) cacheflush(addr, len, DCACHE);
*/
#endif
#ifdef CONFIG_DARWIN
# include <libkern/OSCacheControl.h>
# define cpu_icache_flush(addr, len) sys_icache_invalidate(addr, len)
# define cpu_dcache_flush(addr, len) sys_dcache_invalidate(addr, len)
#endif
#ifdef CONFIG_WINDOWS
# define cpu_icache_flush(addr, len) \
	FlushInstructionCache(GetCurrentProcess(), addr, len);
#endif

#endif
