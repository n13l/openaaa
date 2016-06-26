#include <sys/compiler.h>
#include <sys/cpu.h>
#include <mem/alloc.h>
#include <posix/list.h>
#include <posix/version.h>

DECLARE_LIST(interfaces);

enum abi_call_flags {
	SYM_OPT = 1,
	SYM_REQ = 2
};

struct symbol {
	char *name;                                                       
	void *addr;                                                             
	enum abi_call_flags require;
};


struct interface {
	struct version version;
	const char *name;
	void *symbols[];
};

#define DEFINE_INTERFACE(NAME, VER) \
	struct interface NAME = { \
		.name = #NAME, \
		.version = VER \
	}

int
hihack_system(const char *command);

int 
main(int argc, char *argv[]) 
{
	DEFINE_INTERFACE(sys, VERSION_NULL);

	debug("interface: %s", sys.name);

	//linkmap_add_interface();
	//linkmap_del_interface();
	return 0;
}
