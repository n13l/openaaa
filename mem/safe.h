#ifndef __sys_mem_safe_h__
#define __sys_mem_safe_h__ 

#include <sys/compiler.h>

/*
 * This memset_safe should never be optimized out by the compiler 
 * It is good practice and many security related RFCs require that sensitive
 * data should be removed from memory when it is no long needed so that the 
 * sensitive data does not accidentally end up in the swap files temp file,
 * memory dumps etc.
 *
 * However the optimizing compiler removes the memset function as part of 
 * "dead store removal" optimization sometimes.
 */

static inline void
memset_safe(void *addr, unsigned char byte, size_t size)
{
	volatile u8 *p;
	for (p = (u8 *)addr; size; size--) 
		*p++ = byte;
}

#endif
