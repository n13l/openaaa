#include <sys/compiler.h>
#include <sys/cpu.h>
#include <sys/log.h>
#include <mem/alloc.h>
#include <mem/pool.h>
#include <list.h>
#include <dict.h>
#include <version.h>

void
dict_test1(struct dict *x)
{
	dict_set(x, "attr.example", "test1");
	dict_set(x, "attr.test0", "12345");
	dict_set(x, "attr.test1", "12345");
	dict_set(x, "attr.test2", "12345");
	dict_set(x, "attr.test3", "12345");

	dict_set(x, "attr.aest0", "12345");
	dict_set(x, "attr.best1", "12345");
	dict_set(x, "attr.cest2", "12345");
	dict_set(x, "attr.dest3", "12345");

	dict_set_fmt(x, "attr.testf", "%d", 1234);
	dict_sort(x);
	dict_dump(x);
}

int 
main(int argc, char *argv[]) 
{
	log_open("stdout");
	log_verbose = 4;

	struct mm_pool *mp = mm_pool_create(CPU_PAGE_SIZE, 0);
	struct dict dict;

	dict_init(&dict, mm_pool(mp));
	dict_test1(&dict);

	mm_pool_destroy(mp);
	return 0;
}
