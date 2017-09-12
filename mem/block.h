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

#ifndef __GENERIC_MEM_BLOCK_H__
#define __GENERIC_MEM_BLOCK_H__

#include <sys/compiler.h>
#include <sys/cpu.h>
#include <sys/decls.h>
#include <mem/debug.h>
#include <mem/vm.h>
#include <list.h>

__BEGIN_DECLS

/* fixed-size memory block    */
struct mm_block {
	byte page[CPU_PAGE_SIZE];
};

/* variable-size memory block */
struct mm_vblock {
	/* keep node first because we dont use __container_of() arround */
	struct snode node;
	unsigned int size;
};

static inline void *
vm_vblock_alloc(size_t size)
{
	struct mm_vblock *b = (struct mm_vblock *)vm_page_alloc(size + align_addr(sizeof(*b)));
	b = (struct mm_vblock *)((u8 *)b + size);
	b->size = size;
	snode_init(&b->node);
	return b;
}

void
static inline 
vm_vblock_free(struct mm_vblock *b)
{
	vm_page_free((u8 *)b - b->size, b->size + align_addr(sizeof(*b)));
}

static inline void *
vm_vblock_extend(void *addr, size_t osize, size_t size)
{
	struct mm_vblock *b = (struct mm_vblock *)vm_page_extend(addr, osize, size + align_addr(sizeof(*b)));
	b = (struct mm_vblock *)((u8 *)b + size);
	b->size = size;
	snode_init(&b->node);
	return b;
}


static inline void *
libc_vblock_alloc(size_t size)
{
	struct mm_vblock *b = (struct mm_vblock *)malloc(size + align_addr(sizeof(*b)));
	b = (struct mm_vblock *)((u8 *)b + size);
	b->size = size;
	snode_init(&b->node);
	return b;
}

void
static inline 
libc_vblock_free(struct mm_vblock *b)
{
	free((u8 *)b - b->size);
}

static inline void
mm_vblock_destroy(struct mm_vblock *block)
{
/*	
	struct mm_vblock *it;
	mm_vblock_for_each_safe(block, it)
		vm_vblock_free(block);
*/		
}

__END_DECLS

#endif
