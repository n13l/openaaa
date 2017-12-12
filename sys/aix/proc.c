
#include <sys/compiler.h>
#include <sys/log.h>

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#include <utmp.h>
#include <libgen.h>

#include <sys/protosw.h>
#include <libperfstat.h>
#include <procinfo.h>
#include <sys/proc.h>
#include <sys/procfs.h>

#include <sys/poll.h>

#include <sys/pollset.h>
#include <ctype.h>
#include <sys/mntctl.h>
#include <sys/vmount.h>
#include <limits.h>
#include <strings.h>
#include <sys/vnode.h>

static void* args_mem = NULL;
static char** process_argv = NULL;
static int process_argc = 0;
static char* process_title_ptr = NULL;

char **
setproctitle_init(int argc, char** argv) 
{
	char** new_argv;
	size_t size;
	char* s;
	int i;

	if (argc <= 0)
		return argv;

	process_argv = argv;
	process_argc = argc;

	size = 0;
	for (i = 0; i < argc; i++)
		size += strlen(argv[i]) + 1;

	size += (argc + 1) * sizeof(char*);
	new_argv = malloc(size);
	if (new_argv == NULL)
		return argv;
	args_mem = new_argv;

	s = (char*) &new_argv[argc + 1];
	for (i = 0; i < argc; i++) {
		size = strlen(argv[i]) + 1;
		memcpy(s, argv[i], size);
		new_argv[i] = s;
		s += size;
	}
	new_argv[i] = NULL;
	return new_argv;
}


void
setproctitle(const char *fmt, ...)
{
	char* new_title = malloc(1024);
	memset(new_title, 0, 1023);

        va_list ap;
        va_start(ap, fmt);
	vsnprintf(new_title, 1023, fmt, ap);
        va_end(ap);

	if (new_title == NULL)
		die("no memory");

	if (process_title_ptr != NULL)
		free(process_title_ptr);

	process_title_ptr = new_title;
	process_argv[0] = process_title_ptr;
	if (process_argc > 1)
		process_argv[1] = NULL;

}
