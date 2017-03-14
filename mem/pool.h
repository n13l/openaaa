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
	struct mm_savep save;
	void *avail, *final;
	unsigned int blocksize;
	unsigned int index;
	unsigned int flags;
	unsigned int aligned;
	size_t total_bytes;
	size_t useful_bytes;
#ifdef CONFIG_DEBUG_MEMPOOL
	size_t exhausted_bytes;
	size_t amortized_bytes;
	size_t frag_bytes;
	size_t frag_count;
	size_t blocks_total;
	size_t blocks_used;
	size_t blocks_free;
#endif	
};

static inline void *
__pool_alloc_block(struct mm_pool *pool, size_t size)
{
	struct mm_vblock *block;
	size_t aligned = align_to(size, CPU_ADDR_ALIGN);

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

static inline void *
mm_pool_alloc(struct mm_pool *pool, size_t size)
{
	mem_pool_dbg("size=%d avail=%d ", (int)size, (int)pool->save.avail[0]);
	if (size <= pool->save.avail[0]) {
		void *p = (u8 *)pool->save.final[0] - pool->save.avail[0];
		pool->save.avail[0] -= size;
		return p;
	} 
	return __pool_alloc_block(pool, size);
}

static inline void
mm_pool_destroy(struct mm_pool *pool)
{
	struct mm_vblock *it, *block;
	mem_pool_dbg("pool %p destroyed", pool);

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
mm_pool_create(size_t blocksize, int flags)
{
	struct mm_vblock *block;
	size_t size, aligned = align_addr(sizeof(*block));

	size = max(blocksize, CPU_CACHE_LINE + aligned);
	size = align_to(size, CPU_PAGE_SIZE) - aligned;

	block = vm_vblock_alloc(size);
	struct mm_pool *pool = (void *)((u8 *)block - size);

	mem_pool_dbg("pool %p created with %" PRIuMAX " bytes", 
	             pool, (uintmax_t)blocksize);

	pool->save.avail[0] = size - sizeof(*pool);
	pool->save.final[0] = block;

	pool->final = &pool->final;
	pool->total_bytes  = block->size + aligned;
	pool->blocksize = size; 

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
mm_pool_extend(struct mm_pool *mp, size_t size)
{
	size_t avail = mm_pool_avail(mp);
	if (size <= avail)
		return mm_pool_addr(mp);

	void *ptr = mm_pool_addr(mp);
	if (mp->index) {
		size_t amortized = avail * 2;
		amortized = max(amortized, size);
		amortized = align_to(amortized, CPU_ADDR_ALIGN);

		struct mm_vblock *block = (struct mm_vblock *)mp->save.final[1];
	        struct mm_vblock *next  = (struct mm_vblock *)block->node.next;

		mp->total_bytes = mp->total_bytes - block->size + amortized;

		//size_t aligned = align_addr(sizeof(*block)) + amortized;
		//ptr = vm_vblock_extend(ptr, aligned);
		block = ptr + amortized;

		block->node.next = (struct snode *)next;
		block->size = amortized;

		mp->save.final[1] = block;
		mp->save.avail[1] = amortized;
		mp->final = ptr;
		return ptr;
	} 

	void *addr = mm_pool_alloc(mp, size);
	mp->save.avail[mp->index] += size;
	memcpy(addr, ptr, avail);
	return addr;
}

static inline void *
mm_pool_extend_one(struct mm_pool *mp)
{
	return mm_pool_extend(mp, mm_pool_avail(mp) + 1);
}

static char *
mm_pool_vprintf_at(struct mm_pool *mp, size_t of, const char *fmt, va_list args)
{
	char *b = mm_pool_extend(mp, of + 1) + of;

	va_list args2;
	va_copy(args2, args);
	int len = vsnprintf(b, mm_pool_avail(mp) - of, fmt, args2);
	va_end(args2);

	if (len < 0) {
		do {
			b = mm_pool_extend_one(mp) + of;
			va_copy(args2, args);
			len = vsnprintf(b, mm_pool_avail(mp) - of, fmt, args2);
			va_end(args2);
		} while (len < 0);
	} else if ((unsigned int)len >= mm_pool_avail(mp) - of) {
		b = mm_pool_extend(mp, of + len + 1) + of;
		va_copy(args2, args);
		vsnprintf(b, len + 1, fmt, args2);
		va_end(args2);
	}

	mm_pool_end(mp, b + len + 1);
	return b - of;
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
