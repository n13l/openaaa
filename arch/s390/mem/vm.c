#include <sys/compiler.h>
#include <sys/cpu.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <mem/alloc.h>

#include <errno.h>
#include <string.h>

void *
vm_page_reserve(void)
{
	void *page = NULL;
	return page;
}

void *
vm_page_alloc(u64 size)
{
	void *page = malloc(align_page(size));
	return page;
}

void
vm_page_free(void *page, u64 size)
{
	free(page);
}

void *
vm_page_inquire(void *addr)
{
	return NULL;
}

void *
vm_page_extend(void *page, u64 olen, u64 size)
{
	/* TODO: mremap() on base addr when MM_CONT_ALLOC is used */
	void *addr = vm_page_alloc(size);
	memcpy(addr, page, min(olen, size));
	vm_page_free(page, olen);
	return addr;
}
