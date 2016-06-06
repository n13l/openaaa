#include <stdlib.h>
#include <string.h>

#include <sys/compiler.h>
#include <sys/cpu.h>
#include <mem/alloc.h>

void *
xmalloc(size_t size)
{
	return malloc(size);
}

void *
xmalloc_zero(size_t size)
{
	void *x = xmalloc(size);
	memset(x, 0, size);
	return x;
}

void *
xrealloc(void *addr, size_t size)
{
	return realloc(addr, size);
}

void
xfree(void *ptr)
{
	free(ptr);
}

char *
xstrdup(void *str)
{
	return strdup(str);
}

void
die(const char *fmt, ...)
{
	exit(1);
}
