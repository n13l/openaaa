/*
 * Address space layout randomization (ASLR) 
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#ifdef __i386__
#define GET_CANARY(x) \
	   __asm volatile ("mov %%gs:0x14, %0" : "=r" (x));
#define ASLR_ADDR_FMT   "08x"
#elif defined __x86_64__
#define GET_CANARY(x) \
	   __asm volatile ("mov %%fs:0x28, %0" : "=r" (x));
#define ASLR_ADDR_FMT   "016lx"
#endif

uintptr_t getCanary(void)
{
	uintptr_t x;
	GET_CANARY(x);
	return x;
}


