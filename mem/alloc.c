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

static void *
std_alloc(struct mem *a, size_t size)
{
	return xmalloc(size);
}

static void *
std_realloc(struct mem *a , void *ptr, size_t old_size , size_t new_size)
{
	return xrealloc(ptr, new_size);
}

static void
std_free(struct mem *a, void *ptr)
{
	xfree(ptr);
}

static void *
zero_alloc(struct mem *a, size_t size)
{
	return xmalloc_zero(size);
}

static void *
zero_realloc(struct mem *a , void *ptr, size_t osize, size_t nsize)
{
	ptr = xrealloc(ptr, nsize);
	if (osize < nsize)
		memset((byte *)ptr + osize, 0, nsize - osize);
	return ptr;
}

struct mem mem_std = {
	.alloc   = std_alloc,
	.realloc = std_realloc,
	.free    = std_free,
};

struct mem mem_std_zero = {
	.alloc   = zero_alloc,
	.realloc = zero_realloc,
	.free    = std_free,
};

struct mem mem_ext = {
	.alloc   = zero_alloc,
	.realloc = zero_realloc,
	.free    = std_free,
};

struct mem mem_ext_zero = {
	.alloc   = zero_alloc,
	.realloc = zero_realloc,
	.free    = std_free,
};
