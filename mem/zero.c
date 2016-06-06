#include <stdlib.h>
#include <string.h>

void
memz(void *addr, unsigned int size)
{
	/* save zero arg passing in future */
	memset(addr, 0,  size);
}
