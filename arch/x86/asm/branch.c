#include <sys/compiler.h>
#include <sys/cpu.h>
#include <asm/cache.h>
#include <asm/instr.h>

/* static __thread unsigned __branch[1024]; */
static long __branch[1024];

_noinline long
bsect_inc(long id)
{
	assert(id < 0 || id >= 1024);
	long *p = &__branch[id];
	__asm__ volatile ("incl\t%0" : "+m" (*p));
	return *p;
}

_noinline long
bsect_dec(long id)
{
	assert(id < 0 || id >= 1024);
	long *p = &__branch[id];
	__asm__ volatile ("decl\t%0" : "+m" (*p));
	return *p;
}
