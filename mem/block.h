#ifndef __sys_mem_block_h__
#define __sys_mem_block_h__ 

#include <sys/compiler.h>
#include <sys/cpu.h>
#include <mem/list.h>

/* fixed-size memory block    */
struct mem_block {
	byte page[CPU_PAGE_SIZE];
};

/* variable-size memory block */
struct mem_vblock {
	struct snode node;
	unsigned int size;
};

#define mem_vblock_for_each(item) slist_for_each(item, node)
#define mem_vblock_for_each_safe(item, it) slist_for_each_safe(item, node, it)
#define mem_vblock_unlink(item, prev) slist_remove(&item->node, &prev->node) 

void *
mem_vblock_alloc(unsigned int size);

void
mem_vblock_free(struct mem_vblock *block);

void
mem_vblock_purge(struct mem_vblock *block);

#endif
