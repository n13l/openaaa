#include <sys/compiler.h>
#include <sys/cpu.h>
#include <mem/alloc.h>
#include <mem/cache.h>
#include <list.h>
#include <hash.h>

DEFINE_HASHTABLE(table, 9);

struct person {
	const char *name;
	struct hnode hnode;
};

int 
main(int argc, char *argv[]) 
{
	hash_init(table);

	struct person daniel  = { .name = "Daniel",  .hnode = INIT_HNODE };
	struct person daniela = { .name = "Daniela", .hnode = INIT_HNODE };
	struct person adam    = { .name = "Adam",    .hnode = INIT_HNODE };
	struct person eve     = { .name = "Eve",     .hnode = INIT_HNODE };
	struct person robot   = { .name = "Robot",   .hnode = INIT_HNODE };

	hash_add(table, &daniel.hnode, hash_string(daniel.name));
	hash_add(table, &daniela.hnode, hash_string(daniela.name));
	hash_add(table, &adam.hnode, hash_string(adam.name));
	hash_add(table, &eve.hnode, hash_string(eve.name));
	hash_add(table, &robot.hnode, hash_string(robot.name));

	return 0;
}
