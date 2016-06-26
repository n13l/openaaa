#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include <sys/compiler.h>
#include <mem/alloc.h>
#include <mem/stack.h>

int 
main(int argc, char *argv[]) 
{
	struct mm_pool *mp = mm_create(MM_POOL, CPU_PAGE_SIZE, 0);

	mm_destroy(mp);
	return 0;
}
