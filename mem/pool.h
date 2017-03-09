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

#include <unix/timespec.h>
#include <list.h>
#include <inttypes.h>
#include <assert.h>
#include <string.h>

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
	size_t exhausted_bytes, amortized_bytes;
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

	slist_add(pool->save.final[0], &block->node);

	pool->save.final[0] = block;
	pool->save.avail[0] = pool->blocksize - size;

	return (void *)((u8*)block - pool->blocksize);
}

static inline void *
__pool_alloc_aligned_block(struct mm_pool *pool, size_t size, size_t align)
{
	struct mm_vblock *block;
	size_t aligned = align_to(size, align);

	block = vm_vblock_alloc(aligned);
	slist_add((struct snode *)pool->save.final[1], &block->node);

	pool->index = 1;
	pool->save.final[1] = block;
	pool->save.avail[1] = aligned - size;
	return pool->final = (void *)((u8*)block - aligned);
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
	return __pool_alloc_aligned_block(pool, size, CPU_ADDR_ALIGN);
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
	return __pool_alloc_aligned_block(pool, size, CPU_ADDR_ALIGN);
}

static inline void
mm_pool_destroy(struct mm_pool *pool)
{
	struct mm_vblock *it, *block;
	debug4("pool %p destroyed", pool);

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
		if ((void *)((u8*)block - block->size) == pool)
			break;
		slist_add(pool->avail, &block->node);
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
	 * Support CPU_ADDR_ALIGN for allocated memory buffers.
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
	struct mm_pool *pool = (void *)((u8 *)block - size);

	debug4("pool %p created with %" PRIuMAX " bytes", 
	        pool, (uintmax_t)blocksize);

	pool->save.avail[0] = size - sizeof(*pool);
	pool->save.final[0] = block;

	pool->final = &pool->final;
	pool->total_bytes  = block->size + aligned;
	pool->blocksize = size; 
	pool->threshold = size >> 1;
	pool->parent = object;

	mm_savep_dump(&pool->save);

	return pool;
}

static inline void *
mm_pool_addr(struct mm_pool *mp)
{
	return (u8 *)mp->save.final[mp->index] - mp->save.avail[mp->index];
}
                                                                                
static inline size_t
mm_pool_avail(struct mm_pool *mp)
{
	return mp->save.avail[mp->index];
}

static inline void *
mm_pool_start(struct mm_pool *pool, size_t size)
{
	size_t avail = aligned_part(pool->save.avail[0], CPU_ADDR_ALIGN);
	if (size <= avail) {
		pool->index = 0;
		pool->save.avail[0] = avail;
		return (byte *)pool->save.final[0] - avail;
	} else {
		void *ptr = mm_pool_alloc(pool, size);
		pool->save.avail[pool->index] += size;
		return ptr;
	}
} 

static inline void *
mm_pool_end(struct mm_pool *mp, void *end)
{
	void *p = mm_pool_addr(mp);
	mp->save.avail[mp->index] = (u8*)mp->save.avail[mp->index] - (u8*)end;
	return p;
}

static inline void *
mm_pool_grow(struct mm_pool *mp, size_t size)
{
	if (size <= mm_pool_avail(mp))
		return mm_pool_addr(mp);

	size_t avail = mm_pool_avail(mp);
	void *ptr = mm_pool_addr(mp);

	if (mp->index) {
		size_t amortized = avail * 2;
		amortized = max(amortized, size);
		amortized = align_to(amortized, CPU_ADDR_ALIGN);

		struct mm_vblock *chunk = (struct mm_vblock *)mp->save.final[1];
	        struct mm_vblock *next  = (struct mm_vblock *)chunk->node.next;

		mp->total_bytes = mp->total_bytes - chunk->size + amortized;

		size_t aligned = align_simd(sizeof(*chunk)) + amortized;

		debug("realloc ptr=%p aligned=%d", ptr, (int)aligned);

		ptr = realloc(ptr, aligned);
		chunk = ptr + amortized;

		chunk->node.next = (struct snode *)next;
		chunk->size = amortized;

		mp->save.final[1] = chunk;
		mp->save.avail[1] = amortized;
		mp->final = ptr;
		return ptr;
	} 

	void *p = mm_pool_alloc(mp, size);
	mp->save.avail[mp->index] += size;
	memcpy(p, ptr, avail);
	return p;
}

static inline void *
mm_pool_expand(struct mm_pool *mp)
{
	return mm_pool_grow(mp, mm_pool_avail(mp) + 1);
}

static char *
mm_pool_vprintf_at(struct mm_pool *mp, size_t ofs, const char *fmt, va_list args)
{
	char *ret = mm_pool_grow(mp, ofs + 1) + ofs;
	va_list args2;
	va_copy(args2, args);
	int cnt = vsnprintf(ret, mm_pool_avail(mp) - ofs, fmt, args2);
	va_end(args2);
	if (cnt < 0) {
		do {
			ret = mm_pool_expand(mp) + ofs;
			va_copy(args2, args);
			cnt = vsnprintf(ret, mm_pool_avail(mp) - ofs, fmt, args2);
			va_end(args2);
		} while (cnt < 0);
	} else if ((uint)cnt >= mm_pool_avail(mp) - ofs) {
		ret = mm_pool_grow(mp, ofs + cnt + 1) + ofs;
		va_copy(args2, args);
		vsnprintf(ret, cnt + 1, fmt, args2);
		va_end(args2);
	}

	mm_pool_end(mp, ret + cnt + 1);
	return ret - ofs;
}

_unused static char *
mm_pool_vprintf(struct mm_pool *mp, const char *fmt, va_list args)
{
	mm_pool_start(mp, 1);
	return mm_pool_vprintf_at(mp, 0, fmt, args);
}

_unused static char *
mm_pool_printf(struct mm_pool *p, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	char *addr = mm_pool_vprintf(p, fmt, args);
	va_end(args);
	return addr;
}

#endif
