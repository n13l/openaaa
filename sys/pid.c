#include <sys/compiler.h>
#include <sys/log.h>

#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>

int
pid_write(const char *file)
{
	FILE *f;
	int fd;
	int pid;

	if ((fd = open(file, O_RDWR | O_CREAT, 0644)) == -1) {
		error("Can't open or create %s.", file);
		return 0;
	}

	if (!(f = fdopen(fd, "r+"))) {
		error("Can't open %s.", file);
		close(fd);
		return 0;
	}

	if (flock(fd, LOCK_EX | LOCK_NB) == -1) {
		fscanf(f, "%d", &pid);
		fclose(f);
		error("Can't lock, lock is held by pid %d.", pid);
		return 0;
	}

	pid = getpid();
	if (!fprintf(f,"%d\n", pid)) {
		error("Can't write pid %s", file);
		close(fd);
		return 0;
	}
	fflush(f);

	if (flock(fd, LOCK_UN) == -1) {
		error("Can't unlock pidfile %s.", file);
		close(fd);
		return 0;
	}

	close(fd);
	return pid;
}

int
pid_read(const char *file)
{
	FILE *f;
	if (!(f = fopen(file,"r")))
		return 0;

	int pid;
	fscanf(f,"%d", &pid);
	fclose(f);
	
	if ((!pid) || (pid == getpid()))
		return 0;

	if (kill(pid, 0) && errno == ESRCH)
		return 0;

	return pid;
}
