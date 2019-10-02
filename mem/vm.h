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

#ifndef __MEM_VM_PAGE_H__
#define __MEM_VM_PAGE_H__ 

#include <sys/compiler.h>
#include <sys/cpu.h>

__BEGIN_DECLS

struct vm_info {
	u64 size; /* Current virtual memory usage */
	u64 peak; /* Peak virtual memory usage    */
	u64 rss;  /* Resident set size */
	u64 hwm;  /* Peak resident set size */
	u64 pte;  /* Pagetable entries size */
	u64 swap; /* Swap space used */
};

void *
vm_page_reserve(void);

void *
vm_page_alloc(size_t size);

void
vm_page_free(void *page, size_t size);

void *
vm_page_inquire(void *addr);

void *
vm_page_extend(void *page, size_t orig, size_t size);

int
vm_usage(struct vm_info *vm_info);

__END_DECLS

#endif
