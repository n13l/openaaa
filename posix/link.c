#include <sys/compiler.h>
#include <sys/log.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <libgen.h>

#include <mem/alloc.h>
#include <mem/stack.h>

#include <dlfcn.h>

void *
dlopen_resolve(const char *file, int flags)
{
	/*
	struct stat st;
	if (lstat(file, &st))
		return NULL;

	if (S_ISLNK(st.st_mode)) {
		char *dir  = stk_strdup(file);
		char *path = alloca(FILENAME_MAX);

		dir = dirname(dir);
		readlink(file, path, st.st_size + 1);
		path[st.st_size] = '\0';

		sys_dbg("%s -> %s/%s", file, dir, path);
		file = stk_printf("%s/%s", dir, path);
		return dlopen(file, flags);
	} 

	*/
	return NULL;
//	return dlopen(file, flags);
}
