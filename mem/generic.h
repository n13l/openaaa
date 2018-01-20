/*                                                                              
 * The MIT License (MIT)                       Memory Management debug facility
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
 
#ifndef __MM_GENERIC_H__
#define __MM_GENERIC_H__

#include <sys/compiler.h>
#include <sys/cpu.h>
#include <sys/log.h>
#include <mem/stack.h>
#include <mem/pool.h>
#include <mem/heap.h>
#include <mem/debug.h>
#include <assert.h>

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
 * mm_alloc - allocate memory buffer from stack, pool or heap
 * @mm Optional opaque object representing the memory context
 * @size size of buffer
 */

#define mm1_alloc(... /* mm, size */) \
	({ void *_X = mm_alloc_dispatch(__VA_ARGS__); _X; })

#define mm1_zalloc(...) /* mm, size */ \
	({ void *_X = mm_zalloc_dispatch(__VA_ARGS__); _X; })

#define mm1_flush(mm) \
	do { mm_flush_dispatch(mm); } while(0)

#define mm1_free(mm, addr)

/* save memory state point */
#define mm1_savep(mm) 
/* load memory state point */
#define mm1_loadp(mm)
#define mm1_memdup(mm, addr, size)

#define mm1_strdup(...) /* mm, str */ \
	({ char *_X = mm_strdup_dispatch(__VA_ARGS__); _X; })

#define mm1_strndup(mm, str, size)
#define mm1_strmem(mm, str, size)

/*
 * mm_describe - Return size in bytes of the last allocated memory object 
 */
#define mm1_describe(mm, addr)

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

#define mm1_printf(mm, ...) \
({                                                                            \
	char *_X = mm_printf_dispatch(mm, __VA_ARGS__); _X;                  \
})

#define mm1_vprintf(mm, fmt, args) \
({                                                                            \
	char *_X = mm_vprintf_dispatch(mm, fmt, args); _X;                  \
})


/* Runtime zero-overhead metaprogramming in C language */
#define mm_flush_dispatch(mm) \
do { \
	__build_bug_on(!(pointer_of(mm, struct mm_pool))); \
	mm_pool_flush(mm); \
} while(0)

#define mm_alloc_dispatch(...) \
	macro_dispatcher(mm_alloc_dispatch, __VA_ARGS__)(__VA_ARGS__)

#define mm_alloc_dispatch1(size) \
({ \
	void *_X; _X = malloc(size); _X; \
})

#define mm_alloc_dispatch2(mm, size) \
({ \
	void *_X = NULL; \
	if_pointer_of(mm, struct mm_pool) { \
		_X = mm_pool_alloc((struct mm_pool *)mm, size); \
	} \
	_X; \
})

#define mm_zalloc_dispatch(...) \
	macro_dispatcher(mm_zalloc_dispatch, __VA_ARGS__)(__VA_ARGS__)

#define mm_zalloc_dispatch1(size) \
({ \
	void *_X = NULL; _X = malloc(size); memset(_X, 0, size); _X; \
})

#define mm_zalloc_dispatch2(mm, size) \
({ \
	void *_X = NULL; \
	if_pointer_of(mm, struct mm_pool) { \
		_X = mm_pool_alloc((struct mm_pool *)mm, size); \
 		memset(_X, 0, size); \
	} \
	_X; \
})

#define mm_strdup_dispatch(...) \
	macro_dispatcher(mm_strdup_dispatch, __VA_ARGS__)(__VA_ARGS__)

#define mm_strdup_dispatch1(str) \
({ \
	void *_X = strdup(str); \
	_X; \
})

#define mm_strdup_dispatch2(mm, str) \
({ \
	char *_X = NULL; \
	size_t _SIZE = strlen(str); \
	if_pointer_of(mm, struct mm_pool) { \
		_X = (char *)mm_pool_strdup((struct mm_pool *)mm, _SIZE); \
	}\
	_X; \
})

#define mm_printf_dispatch(mm, ...) \
({ \
	__build_bug_on(!(aryptr_of(mm, char )             ||  \
	                 pointer_of(mm, struct mm_stack ) ||  \
	                 pointer_of(mm, struct mm_pool )  ||  \
	                 pointer_of(mm, struct mm_heap )  )); \
	char *_X; \
	if (aryptr_of(mm, char ))\
		_X = printfa(mm, __VA_ARGS__); \
	else if (pointer_of(mm, struct mm_stack ))\
		_X = printfa(__VA_ARGS__); \
	else if (pointer_of(mm, struct mm_pool ))\
		_X = mm_pool_printf((struct mm_pool *)mm, __VA_ARGS__); \
	else if (pointer_of(mm, struct mm_heap ))\
		_X = printfa(__VA_ARGS__); \
	else abort(); \
	_X; \
})

#define mm_vprintf_dispatch(mm, fmt, args) \
({ \
 	char *_X = NULL;\
	_X; \
})

#endif
