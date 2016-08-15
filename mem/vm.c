#include <sys/compiler.h>
#include <sys/cpu.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <mem/alloc.h>

#include <errno.h>
#include <string.h>

#define VM_PAGE_PROT (PROT_READ | PROT_WRITE)
#define VM_PAGE_MODE (MAP_PRIVATE | MAP_ANON)

void *
vm_page_reserve(void)
{
	void *page = mmap(NULL, 0, VM_PAGE_PROT, VM_PAGE_MODE, -1, 0);
	if (page == (void*)MAP_FAILED)
		die("Cannot mmap reserve virtual memory: %s\n", strerror(errno));
	return page;
}

void *
vm_page_alloc(u64 size)
{
	void *page = mmap(NULL, size, VM_PAGE_PROT, VM_PAGE_MODE, -1, 0);
	if (page == (void*) MAP_FAILED)
		die("Cannot mmap %llu bytes of memory: %s\n", 
		    (unsigned long long)size, strerror(errno));
	return page;
}

void
vm_page_free(void *page, u64 size)
{
	munmap(page, size);
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
