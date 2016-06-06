#ifndef __MEM_SLAB_H__
#define __MEM_SLAB_H__

struct memslab {
	int unused;
};

void
memslab_init(void);

#endif
