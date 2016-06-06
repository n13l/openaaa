#include <sys/compiler.h>
#include <sys/cpu.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdbool.h>

#include <dlfcn.h>

#include "../arch/x86/include/tramp.h"

#include <mem/pool.h>
#include <mem/page.h>

void die(const char *str, ...)
{
	arch_call_intr_vec(3);
	exit(1);

}

void vdie(const char *fmt, va_list args)
{
	arch_call_intr_vec(3);
	exit(1);
}

void giveup(const char *fmt, ...)
{
}

int
main(int argc, char *argv[])
{
	printf("platform: %s\n", CONFIG_PLATFORM);
	printf("cpu.pagesize=%d\n", CONFIG_PAGE_SIZE);
	printf("cpu.pagesize=%d\n", CPU_PAGE_SIZE);
	printf("cpu.struct.align=%d\n", CPU_STRUCT_ALIGN);
	printf("cpu.cacheline=%d\n",  L1_CACHE_BYTES);

	struct mempool *mp = mp_new(CPU_PAGE_SIZE);

	mp_delete(mp);
	return 0;
}
