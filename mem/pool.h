#ifndef __GENERIC_MEM_POOL_H__
#define __GENERIC_MEM_POOL_H__

#include <sys/compiler.h>
#include <sys/cpu.h>
#include <sys/log.h>

#include <mem/debug.h>
#include <mem/alloc.h>
#include <mem/savep.h>
#include <mem/block.h>
#include <mem/generic.h>

#include <posix/timespec.h>
#include <posix/list.h>
#include <inttypes.h>
#include <assert.h>

/* 
 * Allows deterministic behavior on real-time systems avoiding the out of 
 * memory errors.
 *
 * Variable-size block memory pools do need to store allocation metadata for 
 * each allocation, describing characteristics like the size of the allocated
 * block.
 */

struct mm_pool {
	struct mm_pool *parent;
	struct mm_savep save;
	void *avail, *final;
	unsigned int blocksize;
	unsigned int threshold;
	unsigned int index;
	unsigned int flags;
	size_t aligned;
	size_t total_bytes, useful_bytes;
#ifdef CONFIG_DEBUG_MEMPOOL
	size_t frag_bytes;
	size_t frag_count;
#endif	
};

#ifdef ARCH_ENABLE_MEMORY_POOL
#endif

static inline void *
__pool_alloc_threashold(struct mm_pool *pool, size_t size)
{
	struct mm_vblock *block;

	pool->index = 0;
	if (pool->avail) {
		block = pool->avail;
		pool->avail = block->node.next;
	} else 
		block = vm_vblock_alloc(pool->blocksize);

	slist_add_after(pool->save.final[0], &block->node);

	pool->save.final[0] = block;
	pool->save.avail[0] = pool->blocksize - size;

	return (void *)block - pool->blocksize;
}

static inline void *
__pool_alloc_aligned_block(struct mm_pool *pool, size_t size, size_t align)
{
	struct mm_vblock *block;
	size_t aligned = align_to(size, align);

	block = vm_vblock_alloc(aligned);
	slist_add_after((struct snode *)pool->save.final[1], &block->node);

	pool->index = 1;
	pool->save.final[1] = block;
	pool->save.avail[1] = aligned - size;
	return pool->final = (void *)block - aligned;
}

static inline void *
__pool_alloc_avail(struct mm_pool *pool, size_t size, size_t avail)
{
	pool->save.avail[0] = avail - size;
	return (u8*)pool->save.final[0] - avail;
}

#ifdef CONFIG_DEBUG_MEMPOOL
void *
__pool_alloc_aligned(struct mm_pool *pool, size_t size, size_t align);
#else
static inline void *
__pool_alloc_aligned(struct mm_pool *pool, size_t size, size_t align)
{                                                                               
	size_t avail = aligned_part(pool->save.avail[0], align);

	if (size <= avail)
		return __pool_alloc_avail(pool, size, avail);
	if (size <= pool->threshold)
		return __pool_alloc_threashold(pool, size);
	/* This is minimum align size supported right now */
	return __pool_alloc_aligned_block(pool, size, CPU_SIMD_ALIGN);
}
#endif

static inline void *
mm_pool_alloc_aligned(struct mm_pool *pool, size_t size, size_t align)
{                                                                               
	return __pool_alloc_aligned(pool, size, align);
}

static inline void *
mm_pool_alloc(struct mm_pool *pool, size_t size)
{
	if (size <= pool->save.avail[0]) {
		void *p = (u8 *)pool->save.final[0] - pool->save.avail[0];
		pool->save.avail[0] -= size;
		return p;
	} 

	if (size <= pool->threshold)
		return __pool_alloc_threashold(pool, size);

	return __pool_alloc_aligned_block(pool, size, CPU_SIMD_ALIGN);
}

static inline void
mm_pool_destroy(struct mm_pool *pool)
{
	struct mm_vblock *it, *block;
	mem_dbg("mm pool %p destroyed", pool);

	block = pool->save.final[1];
	slist_for_each_delsafe(block, node, it)
		vm_vblock_free(block);

	block = pool->avail;
	slist_for_each_delsafe(block, node, it)
		vm_vblock_free(block);

	block = pool->save.final[0];
	slist_for_each_delsafe(block, node, it)
		vm_vblock_free(block);

}

static inline void
mm_pool_flush(struct mm_pool *pool)
{
	struct mm_vblock *it, *block;

	block = pool->save.final[1];
	slist_for_each_delsafe(block, node, it)
		vm_vblock_free(block);

	block = pool->save.final[0];
	slist_for_each_delsafe(block, node, it) {
		if ((void *)block - block->size == pool)
			break;
		slist_add_after(pool->avail, &block->node);
		pool->avail = block;
	}

	pool->save.final[0] = block;
	pool->save.avail[0] = block ? block->size - sizeof(*pool) : 0;
	pool->save.final[1] = NULL;
	pool->save.avail[1] = 0;
	pool->final = &pool->final;

	snode_init(&pool->save.node);
}

static inline struct mm_pool *
mm_pool_create(struct mm_pool *object, size_t blocksize, int flags)
{
	struct mm_vblock *block;

	/*
	 * Support CPU_PAGE_ALIGN for variable memory blocks.
	 * Support CPU_SIMD_ALIGN for allocated memory buffers.
	 *
	 * TODO:
	 *
	 * MM_ADDR_ALIGN
	 * MM_FAST_ALIGN
	 * MM_LOCK_ALIGN
	 * MM_PAGE_ALIGN
	*/

	size_t size, aligned = align_simd(sizeof(*block));

	size = max(blocksize, CPU_CACHE_LINE + aligned);
	size = align_to(size, CPU_PAGE_SIZE) - aligned;

	block = vm_vblock_alloc(size);
	struct mm_pool *pool = (void *)block - size;

	mem_dbg("mm pool %p created with %" PRIuMAX " bytes", 
	        pool, (uintmax_t)blocksize);

	pool->save.avail[0] = size - sizeof(*pool);
	pool->save.final[0] = block;

	pool->final = &pool->final;
	pool->total_bytes  = block->size + aligned;
	pool->blocksize = size; 
	pool->threshold = size >> 1;

	mm_savep_dump(&pool->save);

	return pool;
}

static inline struct mm_pool *
mm_pool_create_const(const struct mm_pool *pool, size_t size, int flags)
{
	return mm_pool_create((struct mm_pool *)pool, size, flags);
}

#endif
