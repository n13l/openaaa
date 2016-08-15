#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>

size_t
arch_stack_max(void)
{
	struct rlimit limit;
	getrlimit(RLIMIT_STACK, &limit);
	return limit.rlim_max;
}

size_t
arch_stack_cur(void)
{
	struct rlimit limit;
	getrlimit(RLIMIT_STACK, &limit);
	return limit.rlim_cur;
}
size_t
arch_stack_avail(void)
{
	struct rlimit limit;
	memset(&limit,0, sizeof(limit));
	getrlimit(RLIMIT_STACK, &limit);
	return limit.rlim_max - limit.rlim_cur;
}
