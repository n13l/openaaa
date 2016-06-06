#ifndef __SYS_MEMORY_MAP_H__
#define __SYS_MEMORY_MAP_H__

#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <ctype.h>

#include <sys/compiler.h>
#include <sys/decls.h>

__BEGIN_DECLS

struct mmap_operations {
	void (*init)(void *addr);
};

void *
mmap_open(const char *name, int mode, u32 shift, u32 pages);

void
mmap_pages_init(void *addr);

void *
mmap_resize(void *addr, u32 pages);

int
mmap_close(void *addr);

__END_DECLS

#endif/*__M_MAP_H__*/
