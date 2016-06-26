#include <sys/compiler.h>
#include <sys/cpu.h>
#include <mem/alloc.h>
#include <mem/cache.h>
#include <posix/list.h>
#include <posix/hash.h>

DEFINE_HASHTABLE(table, 9);

//DEFINE_HASHATTR(object, name, node) 
//
struct bb {
	byte *addr;
	size_t len;
} bb;

struct person {
	const char *name;
	struct hnode node;
};

int 
main(int argc, char *argv[]) 
{
	hash_init(table);
/*
	struct person daniel  = { .name = "Daniel",  .node = init_hnode };
	struct person daniela = { .name = "Daniela", .node = init_hnode };
	struct person adam    = { .name = "Adam",    .node = init_hnode };
	struct person eve     = { .name = "Eve",     .node = init_hnode };
	struct person robot   = { .name = "Robot",   .node = init_hnode };
*/
	//hash_add(table, person.hnode, person.name);

	return 0;
}
