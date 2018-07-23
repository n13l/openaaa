
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>
#include <dlfcn.h>
#ifdef __sun
#include <procfs.h>
#define ELF_TARGET_ALL
#endif /* __sun */
#include <link.h>
#include "plthook.h"

struct plthook {
    const char *base;
};

static char errmsg[512];

#ifdef PT_GNU_RELRO
static size_t page_size;
#endif

static int plthook_open_executable(plthook_t **plthook_out);
static int plthook_open_shared_library(plthook_t **plthook_out, const char *filename);
static int plthook_open_real(plthook_t **plthook_out, const char *base, const char *filename);
static void set_errmsg(const char *fmt, ...) __attribute__((__format__ (__printf__, 1, 2)));

int plthook_open(plthook_t **plthook_out, const char *filename)
{
    *plthook_out = NULL;
    if (filename == NULL) {
        return plthook_open_executable(plthook_out);
    } else {
        return plthook_open_shared_library(plthook_out, filename);
    }
}

int plthook_open_by_handle(plthook_t **plthook_out, void *hndl)
{
	return -1;
}

int plthook_open_by_address(plthook_t **plthook_out, void *address)
{
	return -1;
}

static int plthook_open_executable(plthook_t **plthook_out)
{
	return -1;
}

static int plthook_open_shared_library(plthook_t **plthook_out, const char *filename)
{
	return -1;
}

__unused static int 
plthook_open_real(plthook_t **plthook_out, const char *base, const char *filename)
{
	return -1;
}

int plthook_enum(plthook_t *plthook, unsigned int *pos, const char **name_out, void ***addr_out)
{
	return EOF;
}

int plthook_replace(plthook_t *plthook, const char *funcname, void *funcaddr, void **oldfunc)
{
	return -1;
}

void plthook_close(plthook_t *plthook)
{
}

const char *plthook_error(void)
{
	return errmsg;
}

__unused static void 
set_errmsg(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(errmsg, sizeof(errmsg) - 1, fmt, ap);
    va_end(ap);
}
