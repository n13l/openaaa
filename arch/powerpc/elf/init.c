#include <sys/compiler.h>
#include <sys/cpu.h>
#include <sys/log.h>
#include <elf/lib.h>
#include <posix/list.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <link.h>

struct linkmap_module {
	struct node n;
	struct mempool *mem;
};

void
elf_init(void)
{
}

/*
int
linkmap_info(struct dl_phdr_info *dl, size_t size, void *data)
{
	const char *name = dl->dlpi_name;

	if (name && !strstr(name, "ssl"))
		return 0;

	sys_dbg("object addr=%p name=%s", (void *)dl->dlpi_addr, dl->dlpi_name);
	for (int i = 0; i < dl->dlpi_phnum; i++) {
		struct elf64_phdr *phdr = (struct elf64_phdr *)&dl->dlpi_phdr[i];

		const char *type = elf_segment_types(phdr->type);
		if (!type)
			continue;

		sys_dbg("hdr[%d] paddr=%p, vaddr=%p type=%s", 
		        i, (void *)phdr->paddr, (void *)phdr->vaddr, type);

	}

	return 0;
}
*/
void
linkmap_init(void)
{
	//dl_iterate_phdr(linkmap_info, NULL);
}

void
linkmap_fini(void)
{
}
