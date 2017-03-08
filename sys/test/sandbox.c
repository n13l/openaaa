#include <sys/compiler.h>
#include <sys/cpu.h>
#include <sys/abi.h>
#include <mem/alloc.h>
#include <list.h>
#include <version.h>

#define DEFINE_SYMBOL(ns, rv, fn, args...) \
	rv ((* ns##_##fn)(args))

#define DECLARE_SYMBOL(ns, rv, fn, args...) \
	_noinline rv ns##_##fn(args)

#define INTERFACE_SYMBOL(ns, fn, mode) \
	(struct symbol) \
	{ .name = stringify(fn), .addr = & ns##_##fn, .flags = mode } 

struct symbol {
	char *name;
	void *addr;
	void *user;
	int flags;
};

struct interface {
	const char *name;
	struct version version;
	struct symbol symbols[];
};

DEFINE_SYMBOL(libc, int, system, const char *);

#define INTERFACE_PROLOGUE(cname, cversion) \
	struct interface cname = { \
		.name = stringify(cname), .version = cversion , \
		.symbols = { 
	
#define INTERFACE_EPILOGUE \
			(struct symbol) { NULL }, \
		} \
	}

#define INTERFACE_VERSION(cversion) \
	 .version = cversion

#define DEFINE_INTERFACE(cname, cversion, csymbols) \
	struct interface cname = { \
		.name = stringify(cname), .version = cversion, \
		.symbols = { \
			(struct symbol) { .name = "test1" }, \
			(struct symbol) { NULL }, \
		} \
	}
/*
INTERFACE_PROLOGUE(libc, MAKE_VERSION(0,0,0))
	INTERFACE_SYMBOL(libc, system, I_REQUIRE), 
INTERFACE_EPILOGUE;
*/
int 
main(int argc, char *argv[]) 
{
//	debug("interface: %s", libc.name);

	//linkmap_add_interface();
	//linkmap_del_interface();
	return 0;
}
