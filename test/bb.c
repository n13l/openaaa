#include <sys/compiler.h>
#include <sys/cpu.h>
#include <sys/log.h>
#include <mem/alloc.h>
#include <mem/pool.h>
#include <list.h>
#include <buffer.h>
#include <version.h>

void
bb_test1(struct mm *mm)
{
	_unused struct bb bb = bb_init(NULL, 0);
}

int 
main(int argc, char *argv[]) 
{
	log_open("stdout", 0);
	log_verbose = 4;

	struct mm_pool *p = mm_pool_create(CPU_PAGE_SIZE, 0);
	bb_test1(mm_pool(p));

	mm_pool_destroy(p);
	return 0;
}
