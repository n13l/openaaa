#include <sys/compiler.h>
#include <sys/cpu.h>
#include <asm/cache.h>
#include <asm/instr.h>

static __thread unsigned __branch[1024];

_noinline int
bsect_inc(int id)
{
	assert(id < 0 || id >= 1024);
	unsigned *p = &__branch[id];
	__asm volatile ("incl\t%0" : "+m" (*p));
	return *p;
}

_noinline int
bsect_dec(int id)
{
	assert(id < 0 || id >= 1024);
	unsigned *p = &__branch[id];
	__asm volatile ("decl\t%0" : "+m" (*p));
	return *p;
}
