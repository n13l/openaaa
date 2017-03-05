#include <sys/compiler.h>
#include <sys/stat.h> 
#include <string.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <unistd.h>
#include <errno.h>
#include <elf/lib.h>

#define REL_DYN ".rela.dyn"                                                    
#define REL_PLT ".rela.plt"

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

static int
elf_read_header(int fd, struct elf64_ehdr **header)
{
    *header = (struct elf64_ehdr *)malloc(sizeof(**header));
    lseek(fd, 0, SEEK_SET);
    read(fd, *header, sizeof(**header));

    return 0;
}

static int
elf_read_section_table(int fd, struct elf64_ehdr *hdr, struct elf64_shdr **table)
{
    size_t size = hdr->shnum * sizeof(*hdr);
    *table = (struct elf64_shdr *)malloc(size);
    lseek(fd, hdr->shoff, SEEK_SET);
    read(fd, *table, size);

    return 0;
}

static int 
elf_read_string_table(int fd, struct elf64_shdr *section, char const **strings)
{
    *strings = (char const *)malloc(section->size);
    lseek(fd, section->offset, SEEK_SET);
    read(fd, (char *)*strings, section->size);

    return 0;
}

static int
elf_read_symbol_table(int fd, struct elf64_shdr *section, struct elf64_sym **table)
{
    *table = (struct elf64_sym *)malloc(section->size);
    lseek(fd, section->offset, SEEK_SET);
    read(fd, *table, section->size);
    return 0;
}

static int 
elf_section_by_index(int fd, size_t index, struct elf64_shdr **section)
{
    struct elf64_ehdr *header = NULL;
    struct elf64_shdr *sections = NULL;

    *section = NULL;
    if (elf_read_header(fd, &header) || elf_read_section_table(fd, header, &sections))
        return errno;

    if (index < header->shnum) {
        *section = (struct elf64_shdr*)malloc(sizeof(**section));
        memcpy(*section, sections + index, sizeof(struct elf64_shdr));
    } else
        return EINVAL;

    free(header);
    free(sections);

    return 0;
}

static int 
elf_section_by_type(int d, size_t const section_type, struct elf64_shdr **section)
{
	struct elf64_ehdr *header = NULL;
	struct elf64_shdr *sections = NULL;
    size_t i;

    *section = NULL;

    if (elf_read_header(d, &header) || elf_read_section_table(d, header, &sections))
        return errno;

    for (i = 0; i < header->shnum; ++i)
        if (section_type == sections[i].type)
        {
            *section = (struct elf64_shdr*)malloc(sizeof(struct elf64_shdr));
            if (NULL == *section) {
                free(header);
                free(sections);
                return errno;
            }

            memcpy(*section, sections + i, sizeof(struct elf64_shdr));

            break;
        }

    free(header);
    free(sections);

    return 0;
}

static int 
elf_section_by_name(int d, char const *section_name, struct elf64_shdr **section)
{
struct elf64_ehdr *header = NULL;
struct elf64_shdr *sections = NULL;
    char const *strings = NULL;
    size_t i;

    *section = NULL;

    if (
        elf_read_header(d, &header) ||
        elf_read_section_table(d, header, &sections) ||
        elf_read_string_table(d, &sections[header->shstrndx], &strings)
        )
        return errno;

    for (i = 0; i < header->shnum; ++i)
        if (!strcmp(section_name, &strings[sections[i].name]))
        {
            *section = (struct elf64_shdr*)malloc(sizeof(struct elf64_shdr));
            if (NULL == *section) {
                free(header);
                free(sections);
                free((void *)strings);

                return errno;
            }

            memcpy(*section, sections + i, sizeof(struct elf64_shdr));

            break;
        }

    free(header);
    free(sections);
    free((void *)strings);

    return 0;
}

static int 
elf_symbol_by_name(int fd, struct elf64_shdr *section, char const *name, 
		   struct elf64_sym **symbol, size_t *index)
{
	struct elf64_shdr *strings_section = NULL;
	char const *strings = NULL;
	struct elf64_sym *symbols = NULL;
	size_t i, amount;

	*symbol = NULL;
	*index = 0;

	if (elf_section_by_index(fd, section->link, &strings_section) ||
	    elf_read_string_table(fd, strings_section, &strings) ||
	    elf_read_symbol_table(fd, section, &symbols))
        	return errno;

	amount = section->size / sizeof(struct elf64_sym);

    for (i = 0; i < amount; ++i)
        if (!strcmp(name, &strings[symbols[i].name])) {
            *symbol = (struct elf64_sym*)malloc(sizeof(struct elf64_sym));
            if (NULL == *symbol) {
                free(strings_section);
                free((void *)strings);
                free(symbols);

                return errno;
            }

            memcpy(*symbol, symbols + i, sizeof(struct elf64_sym));
            *index = i;
            break;
        }

    free(strings_section);
    free((void *)strings);
    free(symbols);

    return 0;
}

int 
elf_module_addr(char const *file, void *handle, void **base)
{
    struct elf64_shdr *dynsym = NULL, *strings_section = NULL;
    char const *strings = NULL;
    struct elf64_sym *symbols = NULL;
    size_t i, amount;
    struct elf64_sym *found = NULL;

    *base = NULL;

    int fd = open(file, O_RDONLY);

    if (fd < 0)
        return errno;

    if (elf_section_by_type(fd, SHT_DYNSYM, &dynsym) ||
        elf_section_by_index(fd, dynsym->link, &strings_section) ||
        elf_read_string_table(fd, strings_section, &strings) ||
        elf_read_symbol_table(fd, dynsym, &symbols))
    {
        free(strings_section);
        free((void *)strings);
        free(symbols);
        free(dynsym);
        close(fd);

        return errno;
    }

    amount = dynsym->size / sizeof(struct elf64_sym);

    /* Trick to get the module base address in a portable way:
     *   Find the first GLOBAL or WEAK symbol in the symbol table,
     *   look this up with dlsym, then return the difference as the base address
     */
    for (i = 0; i < amount; ++i)
    {
        switch(ELF32_ST_BIND(symbols[i].info)) {
        case STB_GLOBAL:
        case STB_WEAK:
            found = &symbols[i];
            break;
        default:
            break;
        }
    }
    if(found != NULL)
    {
        const char *name = &strings[found->name];
        void *sym = dlsym(handle, name); 
        if(sym != NULL)
            *base = (void*)((size_t)sym - found->value);
    }

    free(strings_section);
    free((void *)strings);
    free(symbols);
    free(dynsym);
    close(fd);

    return *base == NULL;
}

void *
elf_hook(char const *file, void const *maddr, char const *name, void const *substitution)
{
    struct elf64_shdr *dynsym = NULL, *rel_plt = NULL, *rel_dyn = NULL;
    struct elf64_sym  *symbol = NULL;
    struct elf64_rel  *rel_plt_table = NULL;
    size_t i, name_index, rel_plt_amount;

    void *original = NULL;
    int fd = open(file, O_RDONLY);

    if (fd < 0)
        return original;

    if (elf_section_by_type(fd, SHT_DYNSYM, &dynsym) || 
        elf_symbol_by_name(fd, dynsym, name, &symbol, &name_index) ||
        elf_section_by_name(fd, REL_PLT, &rel_plt) || 
        elf_section_by_name(fd, REL_DYN, &rel_dyn) )
    { 
        free(dynsym);
        free(rel_plt);
        free(rel_dyn);
        free(symbol);
        close(fd);
        return original;
    }
    free(dynsym);
    free(symbol);

    rel_plt_table = (struct elf64_rel *)(((size_t)maddr) + rel_plt->addr);
    rel_plt_amount = rel_plt->size / sizeof(struct elf64_rel); 

    free(rel_plt);
    free(rel_dyn);

    close(fd);

    for (i = 0; i < rel_plt_amount; ++i)
        if (ELF64_R_SYM(rel_plt_table[i].info) == name_index) {
            original = (void *)*(size_t *)(((size_t)maddr) + rel_plt_table[i].offset);
            *(size_t *)(((size_t)maddr) + rel_plt_table[i].offset) = (size_t)substitution;
            break;
        }

    if (original)
        return original;

    return NULL;
}

