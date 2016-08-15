/*
 * High performance, generic and type-safe memory management
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2015 Daniel Kubec <niel@rtfm.cz> 
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

#include <posix/timespec.h>
#include <posix/list.h>

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

extern struct mm_stack *MM_STACK;
extern struct mm_heap  *MM_HEAP;
extern struct mm_pool  *MM_POOL;

/* 
 * Generic and type-safe memory management structures and functions.
 *
 * o High performance, generic and type-safe memory management
 * o Runtime zero-overhead metaprogramming
 * o Significantly reducing context switch overhead
 * o Significantly reducing function call overhead
 * o Performance for more threads will be yet more significant when
 *   comparing mm_stack, mm_pool with zero locks and atomic operations with 
 *   libc malloc/free.
 *
 * Context switch reduction
 *
 * o In general, the indirect cost of context switch ranges from several 
 *   microseconds to more than one thousand microseconds.
 *
 * o When the overall data size is larger than cache size, the overhead of 
 *   refilling of CPU cache have substantial impact on the cost of context 
 *   switch.
 *
 * Function call reduction and generic type-safe implementation
 *
 * o The generic functions gave us a reduction in execution time, finishing in 
 *   70% of the time required.
 *
 * Generic type-safe implementation
 *
 * o Comparing with their void * counterparts runnig much faster while 
 *   executing less and less expensive CPU instructions.
 */

/*
 * Type-generic macro
 *
 * mm_create - create mapped, heap or stack based memory pool.
 *
 * @size
 * @type
 * @flags
 */

#define mm_create(mm, size, flags) \
	({ void *_X = mm_create_dispatch(mm, size, flags); _X; })

/*
 * mm_destroy - Destroy mm object and release all resource associated
 * @mm 
 *    types: struct mm_pool *
 */

#define mm_destroy(mm) \
	do { mm_destroy_dispatch(mm); } while(0)

/*
 * mm_alloc - allocate memory buffer from stack, pool or heapp
 * @mm Optional opaque object representing the memory context
 * @size size of buffer
 */

#define mm_alloc(... /* mm, size */) \
	({ void *_X = mm_alloc_dispatch(__VA_ARGS__); _X; })

#define mm_alloc_aligned(mm, size, align)
#define mm_zalloc_aligned(mm, size, align)
#define mm_calloc(mm, size, elems)
#define mm_zalloc(mm, size)

#define mm_flush(mm) \
	do { mm_flush_dispatch(mm); } while(0)

#define mm_free(mm, addr)
#define mm_save(mm)
#define mm_rollback(mm)
#define mm_memdup(mm, addr, size)

#define mm_strdup(mm, str) \
	({ char *_X = mm_strdup_dispatch(mm, str); _X; })

#define mm_strndup(mm, str, size)
#define mm_strmem(mm, str, size)

/*
 * mm_describe - Return size in bytes of the last allocated memory object 
 */

#define mm_describe(mm, addr)

/*
  * mm_printf - sends formatted output string to memory management container
  * @mm: memory management object: 
  *   struct mm_pool *, struct mm_stack *, struct mm_heap *
  *
  * note: @mm argument is optional. MM_STACK is used implicitly in that case
  *
  * Pool based allocation with savepoint support:
  *
  *   struct mm_pool *p = mm_create(mm_pool, CPU_PAGE_SIZE, MM_NO_DIE);
  *   const char *v = mm_printf(p, "string=%s, id=%d, "string1", 1);
  *   ...
  *   mm_destroy(p);
  *
  * Explicit and implicit stack based allocation without savepoints:
  *   const char *v = mm_printf("string=%s", "string1"); 
  *   const char *v = mm_printf(MM_STACK, "string=%s, "string1");
  *
  * Stack based allocation with savepoint support:
  *   struct mm_stack *stack = mm_create(MM_STACK, CPU_PAGE_SIZE, MM_NO_GROW);
  *   const char *v = mm_printf(stack, "string=%s", "hi);
  */

#define mm_printf(mm, ...) \
({                                                                            \
	char *_X = mm_printf_dispatch(mm, __VA_ARGS__); _X;                  \
})

#define mm_vprintf(mm, fmt, args) \
({                                                                            \
	char *_X = mm_vprintf_dispatch(mm, fmt, args); _X;                  \
})

#endif
