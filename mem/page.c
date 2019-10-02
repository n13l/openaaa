#include <sys/compiler.h>
#include <sys/log.h>
#include <sys/cpu.h>
#include <list.h>
#include <mem/page.h>

static inline u64
pages_total_bytes(unsigned int bits, unsigned int page_bits, unsigned int total)
{
	return ((1 << bits) + align_to(((1 << page_bits) * total), 1 << bits));
}

int
pages_alloc(struct pages *pages, int prot, int mode,
            int vm_bits, int page_bits, int total)
{
	pages->size  = pages_total_bytes(vm_bits, page_bits, total);
	pages->list  = 0;
	pages->total = pages->avail = total;
	pages->shift = page_bits;

	pages->page = mmap(NULL, pages->size, prot, mode, -1, 0);
	if (pages->page == MAP_FAILED)
		goto failed;
	pages_reset(pages);
	return 0;
failed:
	if (pages->page != MAP_FAILED)
		munmap(pages->page, pages->size);
	return -1;
}

void
pages_reset(struct pages *pages)
{
	page_for_each(pages, struct page *, page) {
		u32 index = page_index(pages, page);
		page->avail = index + 1 >= pages->total ? (u32)~0U : index + 1;
	};
}

int
pages_free(struct pages *pages)
{
	return munmap(pages->page, pages->size);
}
