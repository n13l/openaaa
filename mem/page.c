#include <stdlib.h>
#include <stdio.h>

#include <sys/compiler.h>
#include <sys/cpu.h>
#include <mem/map.h>
#include <mem/page.h>

struct page *
page_alloc_debug(struct pagemap *map)
{
	return NULL;
}

void
page_free_debug(void *page)
{
}
