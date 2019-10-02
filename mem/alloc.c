/*
 * High performance, generic and type-safe memory management
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2015, 2016, 2017, 2018, 2019       Daniel Kubec <niel@rtfm.cz> 
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
#include <list.h>
#include <mem/alloc.h>
#include <stdlib.h>

void *
libc_malloc(struct mm *mm, size_t size)
{
	void *addr = malloc(size);
	if (!addr)
		die("Can not allocate memory size=%jd", (intmax_t)size);
	return addr;
}

void
libc_free(struct mm *mm, void *addr)
{
	free(addr);
}

void *
libc_realloc(struct mm *mm, void *addr, size_t size)
{
	void *p = realloc(addr, size);
	if (!p)
		die("Can not extend memory");
	return p;
}

struct mm mm_libc_ops = {
	.alloc   = libc_malloc,
	.free    = libc_free,
	.realloc = libc_realloc
};

struct mm *mm_libc(void)
{
	return &mm_libc_ops;
}
