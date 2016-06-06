#ifndef __PREFETCH_H__
#define __PREFETCH_H__

#ifdef GCC

static inline void
cpu_prefetch_read(void *addr)
{
	__builtin_prefetch(addr);
}

static inline void
cpu_prefetch_write(void *addr)
{
	__builtin_prefetch(addr, 1);
}

static inline void 
cpu_prefetch_range(void *addr, size_t len)
{
	for (char *c = addr, *e = addr + len; c < e; c += L1_CACHE_STRIDE)
		prefetch_ops_read(c);
}

#endif

#endif/*__M_PREFETCH_H__*/
