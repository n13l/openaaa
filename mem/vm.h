#ifndef __MEM_VM_PAGE_H__
#define __MEM_VM_PAGE_H__ 

#include <sys/compiler.h>
#include <sys/cpu.h>
#include <mem/alloc.h>

void *
vm_page_reserve(void);

void *
vm_page_alloc(u64 size);

void
vm_page_free(void *page, u64 size);

void *
vm_page_inquire(void *addr);

void *
vm_page_extend(void *page, u64 olen, u64 size);

#endif
