/*
  The MIT License (MIT)          Copyright (c) 2015 Daniel Kubec <niel@rtfm.cz>

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.
 */

#ifndef __MEM_PAGE_H__
#define __MEM_PAGE_H__

#include <stdbool.h>
#include <string.h>
#include <errno.h>

#include <sys/compiler.h>
#include <sys/cpu.h>
#include <sys/mman.h>
#include <mem/alloc.h>

//#define PAGEMAP_SHIFT  9

#define PAGE_HDR_MAGIC 0x40000000
#define PAGE_HDR_FREE  0xffffffff
#define PAGE_HDR_PART  0x80000000 /* bit mask for page parts */

struct page;

struct pagemap {
	u64 size;
	u32 magic;
	u32 list;             /* list of free pages */
	u32 avail;            /* number of free pages in list */
	u32 parts;            /* number of large object parts              */
	u32 total;            /* number of pages in map                    */
	u32 shift;            /* page size aligned to power of 2           */
	u16 parts_max;        /* maximum number of object pages            */
	u16 init;
	u16 align;
	struct page *page;
} _align_max;

struct page {
	u32 hdr;              /* page header                               */
	u32 chk;              /* checksum                                  */
	u64 rcu;              /* read copy update lock                     */
	u32 avail;            /* linked list of available pages            */
	u32 hash;             /* linked list of hash collisions            */
	u32 part;             /* linked list of object parts               */
} _align_max;

_unused static void
__page_build_bug_on(void)
{
	__build_bug_on(sizeof(struct pagemap) > CPU_PAGE_SIZE);
}

static inline unsigned int
get_page_size(struct pagemap *map)
{
	return 1 << map->shift;
}

static inline struct page *
get_page(struct pagemap *map, unsigned int index)
{
	return (struct page*)((byte*)map->page + ((size_t)index << map->shift));
}

static inline struct page *
get_page_safe(struct pagemap *map, unsigned int index)
{
	if (unlikely(index > map->total || index == (unsigned int)~0U))
		return NULL;

	return (struct page*)((byte*)map->page + ((size_t)index << map->shift));
}

static inline unsigned int
page_index(struct pagemap *map, struct page *page)
{
	return (size_t)((byte*)page - (byte *)map->page) >> map->shift;
}

static inline unsigned long
page_offset(struct pagemap *map, struct page *page)
{
	return (unsigned long)((byte *)page - (byte *)map->page) >> map->shift;
}

static inline bool
page_avail(struct pagemap *map)
{
	return map->list != (u32)~0U;
}

static inline struct page *
page_alloc(struct pagemap *map)
{
	struct page *page = get_page(map, map->list);
	page->hdr = (u32)0U;
	map->list = page->avail;
	map->avail--;
	return page;
}

static inline struct page *
page_alloc_safe(struct pagemap *map)
{
	struct page *page;
	if ((page = get_page_safe(map, map->list)) == NULL)
		return page;

	page->hdr = (u32)0U;
	map->list = page->avail;
	map->avail--;
	return page;
}

static inline void
page_free(struct pagemap *map, struct page *page)
{
	page->hdr = (u32)~0U;
	page->avail = map->list;
	map->list = page_index(map, page);
	map->avail++;
}

static inline void
page_prefetch(struct page *page, u32 shift, u32 pages)
{
	u32 size = 1U << shift;
	byte addr[size], *ptr = (byte *)page;
	for (unsigned int i = 0; i < pages; i++, ptr += size)
		memcpy(addr, ptr, size);
}

static inline int
page_addr_protect(void *addr, int prot)
{
	prot = PROT_EXEC | PROT_READ;
	int rv;
	uintptr_t page = (uintptr_t)addr & ~(uintptr_t)(CPU_PAGE_SIZE - 1);

	if ((rv = mprotect((void *)page, CPU_PAGE_SIZE, prot)))
		return rv;

	if ((rv = msync((void *)page, CPU_PAGE_SIZE, MS_INVALIDATE)))
		return rv;

	return 0;
}

static inline void
page_range_init(struct pagemap *map, u32 base, u32 range)
{
	struct page *page = NULL;
	for (unsigned int i = base; i < range; i++) {
		page = get_page(map, i);
		page->hdr = page->part = page->hash = (u32)~0U;
		page->avail = i + 1;
	}

	if (page)
		page->avail = (u32)~0U;
}

_unused static unsigned long
pages2mb(uint32_t shift, unsigned long pages)
{
	return (pages * (1 << shift)) >> 20;
}

_unused static unsigned long
mb2pages(uint32_t shift, unsigned long mb)
{
	return (mb << (20 - shift));
}

#define pagemap_walk(map, n, list) 

#define page_for_each(map, type, p) \
	for (type p   = (type)get_page(map, 0), \
	       *__x   = (type)get_page(map, map->total); \
	    p < __x;p = (type)((byte*)p + (1U << map->shift)))

#endif/*__MEM_PAGE_H__*/
