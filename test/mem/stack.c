#include <sys/compiler.h>
#include <sys/log.h>
#include <mem/alloc.h>
#include <mem/stack.h>

int 
main(int argc, char *argv[]) 
{
	/* explicit stack allocation */
	_unused void *addr2 = zalloca(1024);
	_unused const char *v = printfa("hi=%d",1);

	debug("val=%s", v);
	debug("val=%s", printfa("hi=%d",1));
	debug("Testing log");
	debug("Some arg=%s-%d", "Test1", 2);
	return 0;
}
