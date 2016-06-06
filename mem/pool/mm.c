/*
 * The MIT License (MIT)     Mapped Memory Pool for variable-size memory blocks
 *                               Copyright (c) 2015 Daniel Kubec <niel@rtfm.cz> 
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy 
 * of this software and associated documentation files (the "Software"),to deal 
 * in the Software without restriction, including without limitation the rights 
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,ARISING FROM, 
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <sys/compiler.h>
#include <sys/cpu.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <mem/list.h>
#include <mem/block.h>
#include <mem/pool.h>
#include <mem/page.h>
#include <mem/vm.h>

/* 
 * Mapped Memory Pools using mmap()
 *
 * Allows deterministic behavior on real-time systems avoiding the out of 
 * memory errors..
 *
 * Variable-size block memory pools do need to store allocation metadata for 
 * each allocation, describing characteristics like the size of the allocated
 * block.
 */

struct mm_pool_state {
	size_t free[2];
	void *last[2];
	struct snode node;
};

struct mm_pool {
	struct mm_pool_state state;
	void *unused, *last;
	unsigned int block_size;
	unsigned int threshold;
	unsigned int index;
	unsigned int size;
};

static inline void *
pool_alloc_threashold(struct mm_pool *pool, size_t size)
{
	struct mem_vblock *block;

	pool->index = 0;
	if (pool->unused) {
		block = pool->unused;
		pool->unused = block->node.next;
	} else 
		block = vm_page_alloc(pool->block_size);

	block->node.next    = pool->state.last[0];
	pool->state.last[0] = block;
	pool->state.free[0] = pool->block_size - size;
	return (void *)block - pool->block_size;
}

static inline void *
pool_alloc_aligned_block(struct mm_pool *pool, size_t size)
{
	struct mem_vblock *block;
	size_t aligned = _align_struct(size);

	block = vm_page_alloc(aligned);
	block->node.next = pool->state.last[1];

	pool->index = 1;
	pool->state.last[1] = block;
	pool->state.free[1] = aligned - size;
	return pool->last = (void *)block - aligned;
}

static inline void *
pool_alloc_avail(struct mm_pool *pool, size_t size, size_t avail)
{
	pool->state.free[0] = avail - size;
	return (u8*)pool->state.last[0] - avail;
}

void *
mm_pool_alloc_aligned(struct mm_pool *pool, size_t size)            
{                                                                               
	size_t avail = pool->state.free[0] & ~(size_t)(CPU_STRUCT_ALIGN - 1);

	if (size <= avail)
		return pool_alloc_avail(pool, size, avail);
	if (size <= pool->threshold)
		return pool_alloc_threashold(pool, size);

	return pool_alloc_aligned_block(pool, size);
}

void *
mm_pool_alloc(struct mm_pool *pool, size_t size)
{
	if (size <= pool->state.free[0]) {
		void *p = (byte *)pool->state.last[0] - pool->state.free[0];
		pool->state.free[0] -= size;
		return p;
	} 

	if (size <= pool->threshold)
		return pool_alloc_threashold(pool, size);

	return pool_alloc_aligned_block(pool, size);
}

void
mm_pool_delete(struct mm_pool *pool)
{
	mem_dbg("mempool %p", pool);

	mem_vblock_purge(pool->state.last[1]);
	mem_vblock_purge(pool->unused);
	mem_vblock_purge(pool->state.last[0]);
}

void
mm_pool_flush(struct mm_pool *pool)
{
	mem_vblock_purge(pool->state.last[1]);

	struct mem_vblock *it, *mmv = pool->state.last[0];
	mem_vblock_for_each_safe(mmv, it) {
		if ((void *)mmv - mmv->size == pool)
			break;
		mmv->node.next = pool->unused;
		pool->unused = mmv;
	}

	pool->state.last[0] = mmv;
	pool->state.free[0] = mmv ? mmv->size - sizeof(*pool) : 0;
	pool->state.last[1] = NULL;
	pool->state.free[1] = 0;
	pool->state.node.next = NULL;
	pool->last = &pool->last;
}

struct mm_pool *
mm_pool_new(size_t size)
{
	struct mem_vblock *block;

	size = _max(size, CPU_CACHE_LINE + _align_struct(sizeof(*block)));
	size = _align_to(size, CPU_PAGE_SIZE) - _align_struct(sizeof(*block));

	block = mem_vblock_alloc(size);
	struct mm_pool *pool = (void *)block - size;

	mem_dbg("pool %p with %ju bytes long blocks", pool, (uintmax_t)size);

	pool->state = (struct mm_pool_state) {
		.free = { size - sizeof(*pool) }, .last = { block } 
	};

	pool->block_size = size; 
	pool->threshold  = size >> 1;
	pool->last = &pool->last;
	pool->size = block->size + _align_struct(sizeof(*block));

	return pool;
}
