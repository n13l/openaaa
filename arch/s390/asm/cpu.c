#include <sys/compiler.h>
#include <sys/cpu.h>
#include <sys/log.h>

#undef KBUILD_MODNAME
#define KBUILD_MODNAME KBUILD_STR(s390)

const char *
cpu_vendor(void)
{
	debug("cpu.vendor=ibm");
	return "ibm";
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
	debug("cpu.arch=%s", CONFIG_ARCH);
	debug("cpu.bits=%d", sizeof(void *) == 8 ? 64 : 32);
	debug("cpu.pagesize=%d", CPU_PAGE_SIZE);
	debug("cpu.cacheline=%d",  L1_CACHE_BYTES);
	debug("cpu.has.mm.encrypt=1");
	debug("cpu.has.crc32c=%d", cpu_has_crc32c());
}
