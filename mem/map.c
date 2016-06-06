#ifndef __SYS_MEMORY_MAP_H__
#define __SYS_MEMORY_MAP_H__

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sys/compiler.h>
#include <sys/cpu.h>

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#include <sys/decls.h>
#include <sys/missing.h>
#include <mem/page.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE CPU_PAGE_SIZE
#endif

#ifndef PAGE_PROT
#define PAGE_PROT (PROT_READ | PROT_WRITE)
#endif 

/*
static inline int
vm_area_file_trunc(int fd, unsigned long size)
{
	struct stat st;
	if (fstat(fd, &st))
		return -EINVAL;

	if (st.st_size != size && ftruncate(fd, size) == -1)
		return -EINVAL;

	if (fstat(fd, &st) || st.st_size != size)
		return -EINVAL;

	return 0;
}
*/

static inline u64
vm_area_size(u32 shift, u32 total)
{
	return (PAGE_SIZE + _align_to(((1U << shift) * total), PAGE_SIZE));
}

static inline int
vm_area_validate(struct pagemap *map, u64 file_size)
{
	return (map->magic != PAGE_HDR_MAGIC ||
	        map->size  != vm_area_size(map->shift, map->total) ||
		map->size  != file_size);
}

static inline struct pagemap *
vm_area_open(const char *name, int mode)
{
	struct pagemap *map = (struct pagemap *)MAP_FAILED;

	int fd;
	if ((fd = open(name, O_RDWR | O_NOATIME, 0600)) == -1)
		goto failed;

	struct stat st;
        if (fstat(fd, &st))
		goto failed;

        if ((map = mmap(NULL,st.st_size, PAGE_PROT, mode, fd, 0)) == MAP_FAILED)
		goto failed;

	if (vm_area_validate(map, st.st_size))
		goto failed;

	close(fd);

	(*map) = (struct pagemap) { 
		.init = 0,
		.list = 0,
		.page = (struct page *)(((byte *)map) + PAGE_SIZE) 
	};

	return map;
failed:
	if (fd != -1)
		close(fd);

	if (map != MAP_FAILED)
		munmap(map, map->size);	

	return NULL;
}

static inline struct pagemap *
vm_area_init(const char *name, int mode, u32 shift, u32 total)
{
	struct pagemap *map = MAP_FAILED;
	int fd;

	if ((fd = open(name, O_RDWR | O_CREAT | O_NOATIME, 0600)) == -1)
		goto failed;

        u64 size = vm_area_size(shift, total);

        struct stat st;
        if (fstat(fd, &st))
		goto failed;

        if (!S_ISREG(st.st_mode))
		goto failed;

        if (st.st_size != size && ftruncate(fd, size) == -1)
		goto failed;

        if (fstat(fd, &st) || st.st_size != size)
		goto failed;

        if ((map = mmap(NULL, size, PAGE_PROT, mode, fd, 0)) == MAP_FAILED)
		goto failed;

        close(fd);

	(*map) = (struct pagemap) {
		.size  = size,
		.magic = PAGE_HDR_MAGIC,
		.align = CPU_STRUCT_ALIGN,
		.total = total,
		.shift = shift,
		.avail = total,
		.list  = 0,
		.init  = 1,
		.page  = (struct page *)((byte *)map + PAGE_SIZE)
	};

	page_for_each(map, struct page *, page) {

		u32 index = page_index(map, page);
	       	(*page) = (struct page) {
			.hdr   = (u32)~0U,
			.part  = (u32)~0U,
			.hash  = (u32)~0U,
			.avail = index >= map->total ? (u32)~0U : index + 1
		};
	}

	return map;

failed:
	if (fd != -1)
		close(fd);

	if (map != MAP_FAILED)
		munmap(map, map->size);

        return NULL;	
}

void *
mmap_open(const char *name, int mode, u32 shift, u32 total)
{
	struct pagemap *map;

	if ((map = vm_area_open(name, mode)))
		return (void *)map;

	if ((map = vm_area_init(name, mode, shift, total)))
		return (void *)map;

	return NULL;
}

void
mmap_pages_init(void *addr)
{
	struct pagemap *map = (struct pagemap *)addr;
	page_for_each(map, struct page *, page) (*page) = (struct page) {
		.hdr   = (u32)~0U,
		.part  = (u32)~0U,
		.hash  = (u32)~0U,
		.avail = page_index(map, page) >= map->total ? (u32)~0U :
		page_index(map, page) + 1
	};
	
}

void *
mmap_resize(void *addr, u32 pages)
{
/*	
	struct pagemap *map = (struct pagemap *)addr;

	if (map->total >= pages)
		return NULL;

	if ((map = mremap(addr, map->size , pages, 0)) == MAP_FAILED)
		return NULL;

	pages_range_init(map, map->total, pages);
	map->total = pages;

	return map;
*/
	return NULL;	
}

int
mmap_close(void *p)
{
	struct pagemap *map = (struct pagemap *)p;
	return munmap(map, map->size);
}

__END_DECLS

#endif
