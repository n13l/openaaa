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
	void *_X; \
	if_pointer_of(mm, struct mm_pool) \
		_X = mm_pool_alloc((struct mm_pool *)mm, size); \
	if_pointer_of(mm, struct mm_stack) \
		_X = sp_alloc(size); \
	_X; \
})

#define mm_zalloc_dispatch(...) \
	macro_dispatcher(mm_zalloc_dispatch, __VA_ARGS__)(__VA_ARGS__)

#define mm_zalloc_dispatch1(size) \
({ \
	void *_X; _X = malloc(size); memset(_X, 0, size); _X; \
})

#define mm_zalloc_dispatch2(mm, size) \
({ \
	void *_X; \
	if_pointer_of(mm, struct mm_pool) \
		_X = mm_pool_alloc((struct mm_pool *)mm, size); \
	if_pointer_of(mm, struct mm_stack) \
		_X = sp_alloc(size); \
	memset(_X, 0, size); \
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
	void *_X; \
	size_t _SIZE = strlen(str); \
	if_pointer_of(mm, struct mm_pool) \
		_X = mm_pool_alloc((struct mm_pool *)mm, _SIZE + 1); \
	if_pointer_of(mm, struct mm_stack) \
		_X = sp_alloc(_SIZE + 1); \
	memcpy(_X, str, _SIZE + 1); \
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
		_X = sp_printf(mm, __VA_ARGS__); \
	else if (pointer_of(mm, struct mm_stack ))\
		_X = sp_printf(__VA_ARGS__); \
	else if (pointer_of(mm, struct mm_pool ))\
		_X = mm_pool_printf((struct mm_pool *)mm, __VA_ARGS__); \
	else if (pointer_of(mm, struct mm_heap ))\
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
