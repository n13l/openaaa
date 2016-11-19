#include <sys/compiler.h>
#include <elf/lib.h>

_unused static const char * const abi_names[] = {
	[ELFOSABI_SYSV]       = "sysv",
	[ELFOSABI_HPUX]       = "hpux",
	[ELFOSABI_NETBSD]     = "netbsd",
	[ELFOSABI_LINUX]      = "linux",
	[ELFOSABI_SOLARIS]    = "solaris",
	[ELFOSABI_AIX]        = "aix",
	[ELFOSABI_IRIX]       = "arix",
	[ELFOSABI_FREEBSD]    = "freebsd",
	[ELFOSABI_TRU64]      = "true64",
	[ELFOSABI_MODESTO]    = "modesto",
	[ELFOSABI_OPENBSD]    = "openbsd",
	[ELFOSABI_ARM_AEABI]  = "arm aeabi",
	[ELFOSABI_ARM]        = "arm",
	[ELFOSABI_STANDALONE] = "standalone"
};

/* Legal values for (segment type).  */
_unused static const char * const segment_types[] = {
	[PT_NULL]             = "Program header table entry unused",
	[PT_LOAD]             = "Loadable program segment",
	[PT_DYNAMIC]          = "Dynamic linking information",
	[PT_INTERP]           = "Program interpreter",
	[PT_NOTE]             = "Auxiliary information",
	[PT_SHLIB]            = "Reserved",
	[PT_PHDR]             = "Entry for header table itself",
	[PT_TLS]              = "Thread-local storage segment",
	[PT_NUM]              = "Number of defined types",
};

const char *
elf_abi_names(u32 id)
{
	return NULL;
}

const char *
elf_segment_types(u32 id)
{
	return id < array_size(segment_types) ? segment_types[id]: NULL;
}
