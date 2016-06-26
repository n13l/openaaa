#include <sys/compiler.h>
#include <sys/cpu.h>
#include <sys/log.h>
#include <mem/alloc.h>
#include <mem/pool.h>
#include <posix/list.h>

#include <link.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

/*
// Constants for the "filetype" field in llvm::MachO::mach_header and
// llvm::MachO::mach_header_64
MH_OBJECT      = 0x1u,
MH_EXECUTE     = 0x2u,
MH_FVMLIB      = 0x3u,
MH_CORE        = 0x4u,
MH_PRELOAD     = 0x5u,
MH_DYLIB       = 0x6u,
MH_DYLINKER    = 0x7u,
MH_BUNDLE      = 0x8u,
MH_DYLIB_STUB  = 0x9u,
MH_DSYM        = 0xAu,
MH_KEXT_BUNDLE = 0xBu
*/

struct linkmap_module {
	struct node n;
};

int
linkmap_info(struct dl_phdr_info *dl, size_t size, void *data)
{
	_unused const char *name = dl->dlpi_name;

	//sys_dbg("addr=%p name=%s", (void *)dl->dlpi_addr, name);

	return 0;
}

void
linkmap_init(void)
{
	dl_iterate_phdr(linkmap_info, NULL);
}

void
linkmap_fini(void)
{
}

