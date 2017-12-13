/*
 * The MIT License (MIT)
 *                               Copyright (c) 2017 Daniel Kubec <niel@rtfm.cz> 
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy 
 * of this software and associated documentation files (the "Software"),to deal 
 * in the Software without restriction, including without limitation the rights 
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,ARISING FROM, 
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <signal.h>
#include <sys/compiler.h>
#include <sys/cpu.h>
#include <sys/log.h>
#include <sys/irq.h>
#include <sys/mpm.h>

#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

int fd;

static void 
socket_blocking(int sock)
{
	int opts;
	if ((opts = fcntl(sock,F_GETFL)) < 0)
		die("fcntl(F_GETFL)");
	if (fcntl(sock,F_SETFL, (opts & (~O_NONBLOCK))) < 0)
		die("fcntl(F_SETFL)");
	return;
}

static void
socket_init(void)
{
	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		die("Can not create socket");

	struct sockaddr_in addr = {
		.sin_port = htons(6666), .sin_addr.s_addr = 0,
		.sin_addr.s_addr = INADDR_ANY, .sin_family = AF_INET
	};

	if(bind(fd, (struct sockaddr *)&addr,sizeof(addr)) == -1)
		die("Error binding socket");

	socket_blocking(fd);
	listen(fd, 16);
}

static void
socket_fini(void)
{
	if (fd != -1)
		close(fd);
}

static int
ctor(struct task *task)
{
	setproctitle("mpm/%d", task->index);
	info("process:%d pid=%d started", task->index, task->pid);
	return 0;
}

static int
dtor(struct task *task)
{
	return 0;
}

static int
entry(struct task *task)
{
	info("listening tcp://0.0.0.0:6666");
	struct sockaddr_in sa;
	socklen_t len = sizeof(sa);
	int c = accept(fd, (struct sockaddr *)&sa, &len);
	if (c < 0) {
		debug1("accept():%d:%s", errno, strerror(errno));
		return errno;
	}

	socket_blocking(c);

	info("accepted connection from %s:%d", 
	     inet_ntoa(sa.sin_addr), htons(sa.sin_port));
	close(c);

	return 0;
}

_unused static const struct sched_params params = {
	.max_processes        = 4,
	.max_job_parallel     = 2,
	.max_job_queue        = 16,
	.timeout_interuptible = 5,
	.timeout_killable     = 5,
	.timeout_throttled    = 1,
};

int 
main(int argc, char *argv[]) 
{
	irq_init();
	irq_disable();

	argv = setproctitle_init(argc, argv);
	setproctitle("mpmd");

	ctor_task = ctor;
	dtor_task = dtor;
	main_task = entry;

	log_setcaps(15);
	log_verbose = 3;	

	socket_init();

	info("scheduler started.");
	_sched_init();
	_sched_wait();
	_sched_fini();
	info("scheduler stopped.");

	socket_fini();

	return 0;
}
