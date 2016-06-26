#include <sys/compiler.h>
#include <sys/cpu.h>
#include <mem/debug.h>
#include <mem/alloc.h>
#include <mem/pool.h>
	
void *
__pool_alloc_aligned(struct mm_pool *pool, size_t size, size_t align)
{                                                                               
	size_t avail = aligned_part(pool->save.avail[0], align);

	if (size <= avail)
		return __pool_alloc_avail(pool, size, avail);
	if (size <= pool->threshold)
		return __pool_alloc_threashold(pool, size);
	return __pool_alloc_aligned_block(pool, size, CPU_SIMD_ALIGN);
}
