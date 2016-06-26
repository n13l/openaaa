/*
 * The MIT License (MIT)           (MM) Generic and type-safe Memory Management 
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

/* Runtime zero-overhead metaprogramming in C language :) */
#define mm_create_dispatch(mm, size, flags) \
({ \
	__build_bug_on(!(compatible_ptr(mm, const struct mm_pool *) || \
	                 compatible_ptr(mm, struct mm_pool *))); \
	struct mm_pool *_X; \
	if (compatible_ptr(mm, const struct mm_pool *)) { \
		_X = mm_pool_create_const(mm, size, flags); \
	} else if (compatible_ptr(mm, struct mm_pool *)) { \
		_X = mm_pool_create(mm, size, flags); \
	} else abort();  \
	_X; \
})

#define mm_destroy_dispatch(mm) \
do { \
	if (compatible_ptr(mm, const struct mm_pool *)) { \
		mm_pool_destroy(mm); \
	} else if (compatible_ptr(mm, struct mm_pool *)) {\
		mm_pool_destroy(mm); \
	} else abort(); \
} while(0)

#define mm_flush_dispatch(mm) \
do { \
	if (compatible_ptr(mm, const struct mm_pool *)) { \
		mm_pool_flush(mm); \
	} else if (compatible_ptr(mm, struct mm_pool *)) {\
		mm_pool_flush(mm); \
	} else abort(); \
} while(0)

#define mm_alloc_dispatch(...) \
	macro_dispatcher(mm_alloc_dispatch, __VA_ARGS__)(__VA_ARGS__)

#define mm_alloc_dispatch1(size) \
({ \
 	void *_X; _X = sp_alloc(size); _X; \
})

#define mm_alloc_dispatch2(mm, size) \
({ \
	void *_X; \
	_X = \
	__builtin_choose_expr( \
		(__builtin_types_compatible_p(__typeof__(*mm), \
		const struct mm_stack )), sp_alloc(size), \
	__builtin_choose_expr( \
		(__builtin_types_compatible_p(__typeof__(*mm), \
		struct mm_stack )), sp_alloc(size), \
	__builtin_choose_expr( \
		(__builtin_types_compatible_p(__typeof__(*mm), \
		const struct mm_pool )), \
		mm_pool_alloc((struct mm_pool *)mm, size), \
	__builtin_choose_expr( \
		(__builtin_types_compatible_p(__typeof__(*mm), \
		struct mm_pool )), mm_pool_alloc((struct mm_pool *)mm, size), \
	NULL))));\
	_X; \
})

#define mm_strdup_dispatch(mm, str) __extension__ \
({ \
	char *_S = "abc";\
	_S; \
})

#define mm_printf_dispatch(mm, ...) \
({ \
	__build_bug_on(!(compatible_ptr(mm, char *) || \
	                 compatible_ptr(mm, const char *) || \
	                 compatible_ptr(mm, char[]) || \
	                 compatible_ptr(mm, const char[]) || \
	                 compatible_ptr(mm, const struct mm_stack *) || \
	                 compatible_ptr(mm, struct mm_stack *) || \
	                 compatible_ptr(mm, const struct mm_pool *) || \
	                 compatible_ptr(mm, struct mm_pool *) || \
	                 compatible_ptr(mm, const struct mm_heap *) || \
	                 compatible_ptr(mm, struct mm_heap *))); \
	char *_X; \
	if (compatible_ptr(mm, char *))\
		_X = sp_printf(mm, __VA_ARGS__); \
	else if (compatible_ptr(mm, const char *))\
		_X = sp_printf(mm, __VA_ARGS__); \
	else if (compatible_ptr(mm, char[] ))\
		_X = sp_printf(mm, __VA_ARGS__); \
	else if (compatible_ptr(mm, const char[] ))\
		_X = sp_printf(mm, __VA_ARGS__); \
	else if (compatible_ptr(mm, const struct mm_stack *))\
		_X = sp_printf(__VA_ARGS__); \
	else if (compatible_ptr(mm, struct mm_stack *))\
		_X = sp_printf(__VA_ARGS__); \
	else if (compatible_ptr(mm, const struct mm_pool *))\
		_X = sp_printf(__VA_ARGS__); \
	else if (compatible_ptr(mm, struct mm_pool *))\
		_X = sp_printf(__VA_ARGS__); \
	else if (compatible_ptr(mm, struct mm_heap *))\
		_X = sp_printf(__VA_ARGS__); \
	else abort(); \
	_X; \
})

#define mm_vprintf_dispatch(mm, fmt, args) \
({ \
 	char *_X = NULL;\
	_X; \
})


#endif
