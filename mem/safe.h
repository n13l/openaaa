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

#ifndef __sys_mem_safe_h__
#define __sys_mem_safe_h__ 

#include <sys/compiler.h>

/*
 * This memset_safe should never be optimized out by the compiler 
 * It is good practice and many security related RFCs require that sensitive
 * data should be removed from memory when it is no long needed so that the 
 * sensitive data does not accidentally end up in the swap files temp file,
 * memory dumps etc.
 *
 * However the optimizing compiler removes the memset function as part of 
 * "dead store removal" optimization sometimes.
 */

static inline void
memset_safe(void *addr, unsigned char byte, size_t size)
{
	volatile u8 *p;
	for (p = (u8 *)addr; size; size--) 
		*p++ = byte;
}

#endif
