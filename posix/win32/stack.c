#include <windows.h>
#include <inttypes.h>

size_t 
arch_stack_avail(void)
{
	uintptr_t stack = 0;
	uintptr_t sprev = 0;

#ifdef __x86_64__
	__asm__ __volatile__("xchg %%rsp, %0\n\t" : "=r"(sprev) : "0"(stack) );
#else
	__asm__ __volatile__("xchg %%esp, %0\n\t" : "=r"(sprev) : "0"(stack) );
#endif

	static MEMORY_BASIC_INFORMATION mbi;
	VirtualQuery((void *)stack,&mbi,sizeof(mbi));
	return stack - (uintptr_t)mbi.AllocationBase;
}
