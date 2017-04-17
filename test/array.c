#include <sys/compiler.h>
#include <sys/log.h>
#include <array.h>

_unused int array_int[] = {
	1, 2, 3, 4, 5, 6
};
	
_unused char *array_string[] = {
	"test0", "test1", "test2"
};

int 
main(int argc, char *argv[]) 
{
	info("string array size=%u", (uint)array_size(array_string));
	info("int    array size=%u", (uint)array_size(array_int));

	return 0;
}
