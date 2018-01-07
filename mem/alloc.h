/*
 * High performance, generic and type-safe memory management
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2015, 2016, 2017, 2018             Daniel Kubec <niel@rtfm.cz> 
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

#ifndef MM_ALLOC_GENERIC_H__
#define MM_ALLOC_GENERIC_H__

#include <sys/compiler.h>
#include <sys/cpu.h>
#include <sys/log.h>
#include <mem/debug.h>
#include <mem/savep.h>
#include <mem/stack.h>
#include <mem/pool.h>
#include <mem/generic.h>
#include <list.h>
#include <stdarg.h>
#include <assert.h>

/* The memory operations will not call die() for fatal errors. */
#define MM_NO_DIE      (1 << 1)
/* The memory operations will indefinitely repeat the allocation. */
#define MM_NO_FAIL     (1 << 2)
/* The memory region will alloc more blocks on stack, pool or heap */
#define MM_NO_GROW     (1 << 3)
/* The memory operations will not print warnings. */
#define MM_NO_WARN     (1 << 4)
/* The CPU Memory Encryption (EXPERIMENTAL) doc/cpu */
#define MM_HW_ENCRYPT  (1 << 5)  /* Requires MM_PAGE_ALIGN */
/* The buffers of memory allocated is contiguous. */
#define MM_CONT_ALLOC  (1 << 6)  /* Requires MM_PAGE_ALIGN */
/* Specified alignment options for the memory blocks */
#define MM_ADDR_ALIGN  (1 << 7)  /* Aligned to CPU_ARCH_BITS                 */
#define MM_FAST_ALIGN  (1 << 8)  /* Aligned to CPU_SIMD_ALIGN                */
#define MM_LOCK_ALIGN  (1 << 9)  /* Aligned to CPU_CACHE_LINE                */
#define MM_PAGE_ALIGN  (1 << 9)  /* Aligned to CPU_PAGE_SIZE                 */

struct mm {
	void *(*alloc)(struct mm *mm, size_t bytes);
	void (*free)(struct mm *mm, void *addr);
	void *(*realloc)(struct mm *mm, void *addr, size_t bytes);
};

struct mm *mm_libc(void);

/*
 * mm_alloc - allocate memory buffer 
 *
 * @mm   Optional opaque object representing the memory context
 * @size Size of buffer
 */

void *
mm_alloc(struct mm *, size_t size);

void *
mm_zalloc(struct mm *, size_t size);

void *
mm_realloc(struct mm *, void *addr, size_t size);

void *
mm_zrealloc(struct mm *, void *addr, size_t size);

void
mm_free(struct mm *, void *addr);

char *
mm_strmem(struct mm *, const char *str, size_t len);

char *
mm_memdup(struct mm *, const char *ptr, size_t len);

char *
mm_strdup(struct mm *, const char *str);

char *
mm_strndup(struct mm *, const char *str, size_t len);

char *
mm_vprintf(struct mm *, const char *fmt, va_list args);

char *
mm_printf(struct mm *, const char *fmt, ...);

char *
mm_strcat(struct mm *, ...);

char *
mm_fsize(struct mm *mm, u64 num);

#endif
