#ifndef __SYS_MEMORY_MAP_H__
#define __SYS_MEMORY_MAP_H__

#include <sys/compiler.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <ctype.h>

struct mmap_operations {
	void (*init)(void *addr);
};

void *
mmap_file(const char *name, int flags, mode_t mode, int prot, size_t *rsize);

void *
mmap_open(const char *name, int mode, u32 shift, u32 pages);

void
mmap_pages_init(void *addr);

void *
mmap_resize(void *addr, u32 pages);

int
mmap_close(void *addr);

#endif/*__M_MAP_H__*/
