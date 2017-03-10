#include <sys/compiler.h>
#include <sys/cpu.h>
#include <mem/alloc.h>
#include <mem/pool.h>
#include <list.h>
#include <dict.h>
#include <version.h>

int 
main(int argc, char *argv[]) 
{
	printf("hi");
	struct mm_pool *mp = mm_pool_create(CPU_PAGE_SIZE, 0);
	struct dict dict;

	dict_init(&dict, mp);

	dict_set(&dict, "attr.example", "test1");
	dict_set(&dict, "attr.test0", "12345");
	dict_set(&dict, "attr.test1", "12345");
	dict_set(&dict, "attr.test2", "12345");
	dict_set(&dict, "attr.test3", "12345");

	dict_set(&dict, "attr.aest0", "12345");
	dict_set(&dict, "attr.best1", "12345");
	dict_set(&dict, "attr.cest2", "12345");
	dict_set(&dict, "attr.dest3", "12345");


	mm_pool_destroy(mp);
	return 0;
}
