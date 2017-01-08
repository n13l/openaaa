#include <sys/compiler.h>
#include <sys/cpu.h>
#include <elf/lib.h>
	
u32
elf32_get_sym_hash(char *name)
{
	unsigned long g, h;
	for (h = 0; *name; h &= ~g) {
		h = (h << 4) + *name++;
		if ((g = h & 0xF0000000))
			h ^= g >> 24;
	}

	return (u32)h;
}

u64
elf64_get_sym_hash(char *name)
{
	unsigned long g, h;
	for (h = 0; *name; h &= ~g) {
		h = (h << 4) + *name++;
		if ((g = h & 0xF0000000))
			h ^= g >> 24;
	}

	return (u64)h;
}
