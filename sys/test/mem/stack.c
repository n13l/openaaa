#include <sys/compiler.h>
#include <sys/log.h>
#include <mem/alloc.h>
#include <mem/stack.h>

int 
main(int argc, char *argv[]) 
{
	/* explicit stack allocation */
	_unused void *addr1 = mm_alloc(MM_STACK, 1024);
	/* implicit stack allocation */
	_unused void *addr2 = mm_alloc(1024);

	_unused const char *v = mm_printf(MM_STACK, "hi");

	debug("Testing log");
	debug("Some arg=%s-%d", "Test1", 2);
	return 0;
}
