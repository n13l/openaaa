#ifndef __MEM_ALLOCATOR_H__
#define __MEM_ALLOCATOR_H__

#include <sys/compiler.h>
#include <sys/cpu.h>
#include <sys/log.h>

#define ADDR_POISON1  ((void *) 0x00100100)                                     
#define ADDR_POISON2  ((void *) 0x00200200)

#if defined __GNUC__                                                            
#ifndef alloca                                                                  
# define alloca __builtin_alloca                                                
#endif                                                                          
#else                                                                           
# include <alloca.h>                                                            
#endif

#ifdef CONFIG_DEBUG_MEMPOOL
#define mem_dbg(fmt, ...) sys_dbg(fmt, __VA_ARGS__);
#else
#define mem_dbg(fmt, ...) do { } while(0)
#endif

void *
xmalloc(size_t size);

void *
xmalloc_zero(size_t size);

void *
xrealloc(void *addr, size_t size);

void
xfree(void *ptr);

#endif
