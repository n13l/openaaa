#ifndef __MEM_SLAB_H__
#define __MEM_SLAB_H__

struct mem_slab {
	int unused;
};

void
memslab_init(void);

#endif
