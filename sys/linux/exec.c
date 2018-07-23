#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <memory.h>
//#include <linux/limits.h>
#include <libgen.h>
#include <sys/types.h>

size_t
get_library_address(const char *libname)
{
	char path[256];
	char buff[256];
	int len_libname = strlen(libname);
	FILE* file;
	size_t  addr = 0;

	snprintf(path, sizeof path, "/proc/%d/smaps", getpid());
	file = fopen(path, "rt");
	if (file == NULL)
		return 0;

	while (fgets(buff, sizeof buff, file) != NULL) {
		int  len = strlen(buff);
		if (len > 0 && buff[len-1] == '\n') {
			buff[--len] = '\0';
		}
		if (len <= len_libname || 
		    memcmp(buff + len - len_libname, libname, len_libname))
			continue;
		
		size_t start, end, offset;
		char flags[4];
		if (sscanf(buff, "%zx-%zx %c%c%c%c %zx", &start, &end,
	           &flags[0], &flags[1], &flags[2], &flags[3], &offset) != 7)
			continue;

		if (flags[0] != 'r' || flags[2] != 'x') {
			continue;
		}
		addr = start - offset;
		break;
	}
	fclose(file);
	return addr;
}

const char *
get_process_file(void)
{
	char file[PATH_MAX];
	readlink("/proc/self/exe", file, sizeof(file) - 1);
	return strdup(file);
}
