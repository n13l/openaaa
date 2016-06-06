#ifndef __sys_mem_safe_h__
#define __sys_mem_safe_h__ 

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
memset_safe(void *addr, size_t size)
{
	for (volatile u8 *p = (u8*)addr; size--) 
		*p++ = 0;
}

#endif
