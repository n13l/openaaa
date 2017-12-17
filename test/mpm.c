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

#ifndef CONFIG_WIN32

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

#include <net/proto.h>
#include <net/ip/proto.h>

int fd;

static void
socket_init(void)
{
	struct sockaddr_in6 sa = {
		.sin6_family = AF_INET6,
		.sin6_port   = htons(6666),  
		.sin6_addr   = in6addr_any
	};

	if ((fd = socket(AF_INET6, SOCK_STREAM, 0)) == -1)
		die("Can not create socket");

	socket_reuseaddr(fd);
	socket_blocking(fd);

	if (bind(fd, (struct sockaddr *)&sa,sizeof(sa)) == -1)
		die("Error binding socket");
	if (listen(fd, 16) == -1)
		die("Error listen socket");
}

static void
socket_fini(void)
{
	if (fd != -1)
		close(fd);
}

void
main_init(void)
{
}

void
main_fini(void)
{
}

static int
ctor(struct task *task)
{
	setproctitle("mpm/%d", task->index);
	debug1("process pid: %d started", task->pid);
	return 0;
}

static int
dtor(struct task *task)
{
	return 0;
}

static int
entry(struct task *proc)
{
	struct ip_peer ip = { .len = sizeof(ip.sa) };

	do {

	if ((ip.fd = accept(fd, NULL, NULL)) < 0) {
		debug3("accept():%d:%s", errno, strerror(errno));
		return errno;
	}

	socket_blocking(ip.fd);
	getpeername(ip.fd, (struct sockaddr *)&ip.sa, &ip.len);
	if(inet_ntop(AF_INET6, &ip.sa.sin6_addr, ip.name, sizeof(ip.name)))
		info("Accepted connection from %s:%d", 
		     ip.name, htons(ip.sa.sin6_port));

	const char *arg = "test";
	int id = sched_workque(proc, arg);
	info("workque id=%d", id);

	close(ip.fd);
	info("Connection closed with %s:%d", ip.name, htons(ip.sa.sin6_port));

	} while(1);
	return 0;
}

static const struct sched_params sched_params = {
	.max_processes        = 4,     /* number of processes                */
	.max_job_parallel     = 2,     /* number of running queued processes */
	.max_job_queue        = 8,     /* size of the workqueue              */
	.max_job_unique       = 1,     /* maximum unique jobs                */
	.timeout_interuptible = 5,     /* timeout for interuptible code area */
	.timeout_killable     = 5,     /* timeout before process is killed   */
	.timeout_throttled    = 1,     /* slowdown on trashing / fatal errors */
	.timeout_status       = 360,   /* 5 minutes for process status       */
};

static const struct sched_calls sched_calls = {
	.init = main_init,
	.fini = main_fini,
	.ctor = ctor,
	.dtor = dtor,
	.entry = entry
};

static const struct mpm_module mpm_module = {
	.mpm_model    = MPM_HYBRID,    /* threads in dedicated processes     */
	.cpu_model    = CPU_DEDICATED, /* dedicated process workers          */
	.net_model    = NET_ROUNDROBIN,
	.sched_params = &sched_params,
	.sched_calls  = &sched_calls
};

const char *pidfile = "/var/run/mpmd.pid";

int 
main(int argc, char *argv[])
{
	irq_init();
	irq_disable();

	int pid;
	if ((pid = pid_read(pidfile)))
		die("process already running pid: %d\n", pid);

	if (!pid_write(pidfile))
		die("can't write pid file: %s\n", pidfile);

	argv = setproctitle_init(argc, argv);
	setproctitle("mpmd");

	ctor_task = ctor;
	dtor_task = dtor;
	main_task = entry;

	log_setcaps(15);
	log_verbose = 2;

	socket_init();

	info("scheduler started.");
	_sched_start(&mpm_module);
	_sched_wait(&mpm_module);
	_sched_stop(&mpm_module);
	info("scheduler stopped.");

	socket_fini();

	return 0;
}
#else
int
main(int argc, char *argv[])
{
	return 0;
}
#endif
