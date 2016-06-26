#include <sys/compiler.h>
#include <sys/cpu.h>
#include <sys/log.h>
#include <elf/lib.h>

#undef KBUILD_MODNAME
#define KBUILD_MODNAME KBUILD_STR(arm)

const char *
cpu_vendor(void)
{
	debug("cpu.vendor=arm");
	return "arm";
}

int
cpu_has_cap(int capability)
{
	return 0;
}

int
cpu_has_crc32c(void)
{
	return 0;
}

void
cpu_dump_extension(void)
{
}
