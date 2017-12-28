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
#include <mem/alloc.h>
#include <mem/pool.h>

#include <buffer.h>
#include <list.h>
#include <dict.h>

#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#include <net/proto.h>
#include <net/stack.h>

int fd;

struct ip_peer {
	struct sockaddr_in6 sa;
	socklen_t len;
	char name[INET6_ADDRSTRLEN];
	int fd;
};


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

static int
worksvc_ctor(struct task *proc)
{
	debug1("worksvc pid: %d started", proc->pid);
	return 0;
}

static int
worksvc_dtor(struct task *proc)
{
	debug1("worksvc pid: %d exiting", proc->pid);
	return 0;
}

static int
worksvc_entry(struct task *proc)
{
	return 0;
}

static int
process_ctor(struct task *proc)
{
	setproctitle("mpm/%d", proc->index);
	debug1("process pid: %d started", proc->pid);
	return 0;
}

static int
process_dtor(struct task *proc)
{
	debug1("process pid: %d exiting", proc->pid);
	return 0;
}

static int
workque_add(struct task *proc, int fd, const char *arg)
{
	struct bb bb = { .addr = alloca(PIPE_BUF), .len = PIPE_BUF};

	int size = strlen(arg);
	for (u8 *u = (u8*)arg; size; size--, u++) 
		if (*u == '\n') *u = 0;

	int id = sched_workque(proc, arg);
	debug2("workque id=%d added", id);

	snprintf(bb.addr, bb.len - 1, "%d\n", id);
	write(fd, bb.addr, strlen(bb.addr));
	
	return 0;
}

static int
workque_status(struct task *proc, int fd, const char *arg)
{
	int size, rv, id = atoi(arg);

	struct bb bb = { .addr = zalloca(PIPE_BUF), .len = PIPE_BUF};
	struct task_status *status = (struct task_status *)bb.addr;

	if ((rv = sched_getstat(proc, id, status)))
		goto exit;
	if (status->state == TASK_RUNNING)
		goto done;
	if (status->state != TASK_FINISHED)
		goto exit;
	if ((size = sched_getcbuf(proc, id, bb.addr, PIPE_BUF)) < 1)
		goto exit;

	struct mm_pool *mp = mm_pool_create(CPU_PAGE_SIZE, 0);

	struct dict dict;
	dict_init(&dict, mp);
	dict_unpack(&dict, bb.addr, size);
	dict_dump(&dict);

	dict_pack(&dict, bb.addr, PIPE_BUF);

	mm_pool_destroy(mp);
	write(fd, bb.addr, strlen(bb.addr));

done:
	write(fd, "1", 1);
	return 0;
exit:
	error("operation status id=%d failed", id);
	snprintf(bb.addr, bb.len - 1, "%d\n", rv);
	write(fd, bb.addr, strlen(bb.addr));
	return 1;
}

static int
process_entry(struct task *proc)
{
	struct ip_peer ip = { .len = sizeof(ip.sa) };

	do {

	if ((ip.fd = accept(fd, NULL, NULL)) < 0)
		goto error;

	socket_blocking(ip.fd);
	getpeername(ip.fd, (struct sockaddr *)&ip.sa, &ip.len);

	const char *from = inet_ntopa(AF_INET6, &ip.sa.sin6_addr);
	debug1("Accepted connection from %s:%d", from, htons(ip.sa.sin6_port));

	char buffer[8192] = {0};
	int rv = read(ip.fd, buffer, sizeof(buffer));
	if (rv < 1)
		goto error;
	buffer[rv] = 0;

	if (!strncmp(buffer, "add", 3)) {
		const char *arg = buffer + 3;
		workque_add(proc, ip.fd, arg);
	} else if (!strncmp(buffer, "status", 6)) {
		const char *arg = buffer + 7;
		workque_status(proc, ip.fd, arg);
	}

	close(ip.fd);
	debug1("Connection closed with %s:%d", from, htons(ip.sa.sin6_port));

	} while(1);
	return 0;

error:
	debug1("%d:%s", errno, strerror(errno));
	return 1;
}

static int
workque_ctor(struct task *proc)
{
	setproctitle("mpm id=%d", proc->id);
	debug1("workque pid: %d started", proc->pid);
	return 0;
}

static int
workque_dtor(struct task *proc)
{
	debug1("workque pid: %d exiting", proc->pid);
	return 0;
}

static int
workque_entry(struct task *proc)
{
	struct dict dict;
	struct bb bb = { .addr = alloca(PIPE_BUF), .len = PIPE_BUF};

	const char *arg = task_arg(proc);
	debug1("workque pid: %d id=%d arg=%s", proc->pid, proc->id, arg);

	struct mm_pool *mp = mm_pool_create(CPU_PAGE_SIZE, 0);

	dict_init(&dict, mp);
	dict_set(&dict, "tx.id",   "1");
	dict_set(&dict, "tx.type", "2");
	dict_sort(&dict);

	int size = dict_pack(&dict, bb.addr, bb.len);
	if (size < 1)
		goto exit;

	sched_setcbuf(proc, proc->id, bb.addr, size);
exit:
	mm_pool_destroy(mp);
	return 0;
}

static const struct sched_params sched_params = {
	.max_processes        = 4,     /* number of processes                */
	.max_job_parallel     = 2,     /* number of running queued processes */
	.max_job_queue        = 8,     /* size of the workqueue              */
	.max_job_unique       = 0,     /* maximum unique jobs                */
	.timeout_interuptible = 15,    /* timeout for interuptible code area */
	.timeout_killable     = 5,     /* timeout before process is killed   */
	.timeout_throttled    = 1,     /* slowdown on trashing / fatal errors */
	.timeout_status       = 360,   /* 5 minutes for process status       */
};

static const struct sched_callbacks sched_callbacks = {
	.worksvc = {
		.ctor  = worksvc_ctor, 
		.dtor  = worksvc_dtor, 
		.entry = worksvc_entry
	},
	.workque = {
		.ctor  = workque_ctor, 
		.dtor  = workque_dtor, 
		.entry = workque_entry
	},
	.process = {
		.ctor  = process_ctor, 
		.dtor  = process_dtor, 
		.entry = process_entry
	},
};

static const struct mpm_module mpm_module = {
	.mpm_model       = MPM_HYBRID,    /* threads in dedicated processes  */
	.cpu_model       = CPU_DEDICATED, /* dedicated process workers       */
	.net_model       = NET_ROUNDROBIN,
	.params    = &sched_params,
	.callbacks = &sched_callbacks
};

const char *pidfile = "/var/run/mpmd.pid";

int 
main(int argc, char *argv[])
{
	irq_init();
	irq_disable();

	int pid;
	if ((pid = pid_read(pidfile)))
		die("process already running pid: %d", pid);
	if (!pid_write(pidfile))
		die("can't write pid file: %s", pidfile);

	argv = setproctitle_init(argc, argv);
	setproctitle("mpmd");

	log_setcaps(15);
	log_verbose = 2;

	const char *verb = getenv("MPM_VERBOSE");
	if (verb)
		log_verbose = atoi(verb);

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
