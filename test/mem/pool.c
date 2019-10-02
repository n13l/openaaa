#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include <sys/compiler.h>
#include <list.h>
#include <mem/alloc.h>
#include <mem/pool.h>

int 
main(int argc, char *argv[]) 
{
	struct mm_pool *mp = mm_pool_create(CPU_PAGE_SIZE, 0);

	mm_pool_destroy(mp);
	return 0;
}
