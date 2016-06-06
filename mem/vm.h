#ifndef __SYS_VM_block_h__
#define __SYS_VM_block_h__ 

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
vm_page_realloc(void *page, u64 olen, u64 size);

#endif
