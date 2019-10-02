/*
 * High performance, generic and type-safe memory management
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2012-2018                            OpenAAA <openaaa@rtfm.cz>
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

#ifndef __MM_POOL_H__
#define __MM_POOL_H__

#include <sys/compiler.h>
#include <sys/cpu.h>
#include <sys/log.h>
#include <mem/alloc.h>
#include <mem/savep.h>
#include <mem/block.h>
#include <list.h>
#include <inttypes.h>
#include <assert.h>
#include <string.h>

/* 
 * Allows deterministic behavior on real-time systems 
 *
 * Variable-size block memory pools do need to store allocation metadata for 
 * each allocation, describing characteristics like the size of the allocated
 * block.
 */

struct mm;
struct mm_pool {
	struct mm mm;
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

extern struct mm mm_pool_ops;

__BEGIN_DECLS
struct mm *mm_pool(struct mm_pool *);

void *
mm_pool_alloc(struct mm_pool *pool, size_t size);

void *
mm_pool_realloc(struct mm_pool *pool, void *addr, size_t size);

void
mm_pool_free(void *addr);

void *
mm_pool_zalloc(struct mm_pool *pool, size_t size);

void
mm_pool_destroy(struct mm_pool *pool);

void
mm_pool_flush(struct mm_pool *pool);

struct mm_pool *
mm_pool_overlay(void *block, size_t blocksize);
	
struct mm_pool *
mm_pool_create(size_t blocksize, int flags);
  
size_t
mm_pool_avail(struct mm_pool *p);

size_t
mm_pool_size(struct mm_pool *p);

void *
mm_pool_extend(struct mm_pool *p, size_t size);

char *
mm_pool_vprintf(struct mm_pool *p, const char *fmt, va_list args);

char *
mm_pool_printf(struct mm_pool *, const char *fmt, ...);

__END_DECLS

#endif
