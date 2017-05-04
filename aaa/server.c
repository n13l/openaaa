#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h> 
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>                                                         
#include <netinet/in.h>                                                         
#include <arpa/inet.h>
#include <sched.h>

#include <sys/compiler.h>
#include <sys/cpu.h>
#include <sys/log.h>
#include <sys/irq.h>
#include <sys/types.h>
#include <unix/timespec.h>

#include <mem/alloc.h>
#include <mem/pool.h>

#include <list.h>
#include <dict.h>
#include <hash.h>

#include <atomic.h>
#include <spinlock.h>

#include <aaa/lib.h>
#include <aaa/prv.h>

#define EV_API_STATIC 1
#define EV_STANDALONE 1
#define EV_MINIMAL 1
#define EV_CHILD_ENABLE 1
#define EV_IDLE_ENABLE 1
#define EV_EMBED_ENABLE 1
#define EV_USE_POLL 0
#define EV_MULTIPLICITY 1
#define EV_PERIODIC_ENABLE 0
#define EV_STAT_ENABLE 0
#define EV_FORK_ENABLE 1
#define EV_GENWRAP 0
#define EV_AVOID_STDIO 0
#define EV_NO_THREADS 0

#include <sys/ev/ev.c>

sig_atomic_t request_shutdown = 0;
sig_atomic_t request_restart  = 0;
sig_atomic_t request_info     = 0;

int sched_processes           = 1;
int sched_workers             = 4;
int sched_gracefull_timeout   = 15; /* wait maximum 15secs for subprocesses */

enum task_type {
	TASK_TYPE_NONE    = 0,
	TASK_TYPE_DISP,   
	TASK_TYPE_PROC,   
	TASK_TYPE_WORK,   
	TASK_TYPE_LSNR,   
	TASK_TYPE_JOB
};

enum task_state {
	TASK_STATE_NONE   = 0,
	TASK_STATE_WORK   = 1,
	TASK_STATE_STOP   = 2,
	TASK_STATE_CONT   = 3,
	TASK_STATE_INIT   = 4,
	TASK_STATE_FINI   = 5,
};

static const char * const task_type_names[] = {
	[TASK_TYPE_NONE]  = "none",
	[TASK_TYPE_DISP]  = "dispatcher",
	[TASK_TYPE_PROC]  = "process",
	[TASK_TYPE_WORK]  = "worker",
	[TASK_TYPE_LSNR]  = "listener",
	[TASK_TYPE_JOB]   = "job",
};

static const char * const task_state_names[] = {
	[TASK_STATE_NONE]  = "none",
	[TASK_STATE_WORK]  = "work",
	[TASK_STATE_INIT]  = "init",
	[TASK_STATE_FINI]  = "fini",
};

struct task {
	pid_t ppid;
	pid_t pid;
	unsigned int index;
	enum task_type  type;
	enum task_state state;
	struct ev_loop *loop;
	struct ev_timer timer_watcher;
	struct ev_idle idle_watcher;
	struct ev_prepare prepare_watcher;
	struct ev_check check_watcher;
	struct ev_signal signals[32];
	struct ev_signal sigint_watcher;
	struct ev_signal sigterm_watcher;
	struct ev_signal sighup_watcher;
	struct ev_signal sigusr1_watcher;
	struct ev_child child_watcher;
	struct list list;
	struct node node;
	int running;
	int workers;
	u64 version;
	void *user;
} task_disp;

int
task_type(void)
{
	return getpid() == gettid();
}

void
task_user_set(struct task *task, void *data)
{
	task->user = data;
}

void *
task_user_get(struct task *task)
{
	return task->user;
}

static void
huphandler(int signo, siginfo_t *info, void *context)
{
	debug3("signum=%d reason=%s processed", signo, strsignal(signo));
	request_restart = 1;
}


static void
task_status(int id, int status)
{
	if (WIFEXITED(status))
		info("process pid=%d exited, status=%d", id, WEXITSTATUS(status));
	else if (WIFSIGNALED(status))
		info("process pid=%d killed by signal %d (%s)", id, WTERMSIG(status), 
		     strsignal(WTERMSIG(status)));
	else if (WIFSTOPPED(status))
		info("process pid=%d stopped by signal %d", id, WSTOPSIG(status));
	else if (WIFCONTINUED(status))
		info("process pid=%d continued", id);
}

static void
sighandler(struct ev_loop *loop, ev_signal *w, int revents)
{
	if (w->signum == SIGINT)
		write(1, "\n", 1);

	debug3("signum=%d reason=%s processed", w->signum, strsignal(w->signum));
	if (w->signum == SIGTERM || w->signum == SIGINT)
		request_shutdown = 1;
	if (w->signum == SIGHUP)
		request_restart = 1;
	if (w->signum == SIGUSR1) {
		request_info = 1;
		info("workers=%d running=%d", task_disp.workers, task_disp.running);
	}

	if (w->signum == SIGSEGV) {
		/* generate coredump */
		signal(w->signum, SIG_DFL);
		kill(getpid(), w->signum);
	}

	ev_break(loop, EVBREAK_ALL);
}

static void
chld_handler(EV_P_ ev_child *w, int revents)
{
	if ((WIFEXITED(w->rstatus)) || (WIFSIGNALED(w->rstatus)))
		ev_child_stop (EV_A_ w);

	task_status(w->rpid, w->rstatus);

	struct task *c;
	list_for_each_item(task_disp.list, c, node) {
		if (w->rpid != c->pid)
			continue;
		if (WIFEXITED(w->rstatus) || WIFSIGNALED(w->rstatus)) {
			task_disp.running--;
			c->state = TASK_STATE_NONE;
		}
	}

	ev_break(loop, EVBREAK_ALL);
}

static void
timer(EV_P_ ev_timer *w, int revents)
{
//	debug3("timer");
	//ev_timer_stop (EV_A_ w);
}

static void
idle(struct ev_loop *loop, ev_idle *w, int revents)
{
	debug3("idle");
}

static void
prepare(struct ev_loop *loop, ev_prepare *w, int revents)
{
	irq_enable();
}

static void
check(struct ev_loop *loop, ev_check *w, int revents)
{
	irq_disable();
}

#if (EV_USE_SIGNALFD == 1)
static void
signal_norace(struct task *task)
{
	debug("signalfd available");
}
#else
static void
signal_norace(struct task *task)
{
	ev_prepare_init(&task->prepare_watcher, prepare);
	ev_prepare_start(task->loop, &task->prepare_watcher);
	ev_check_init(&task->check_watcher, check);
	ev_check_start(task->loop, &task->check_watcher);
}
#endif

static int fd = -1;
static int port = 8888;

static void 
udp_init(void)
{
	if ((fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
		die("Cannot create UDP socket: %s", strerror(errno));

	int one = 1;
	if (setsockopt(fd , SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0)
		die("Cannot set SO_REUSEADDR: %s", strerror(errno));

	struct timeval tv = {.tv_sec = 10, .tv_usec = 0 };
	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv,sizeof(tv)) < 0)
		die("SO_RCVTIMEO");

	struct sockaddr_in in = {
		.sin_family = AF_INET,
		.sin_port = htons(port),
		.sin_addr.s_addr = INADDR_ANY
	};

	if (bind(fd, (struct sockaddr *) &in, sizeof(in)) < 0)
		die("Cannot bind udp socket: %s", strerror(errno));

}

int
sched_idle(struct task *task)
{
	if (task->type == TASK_TYPE_DISP)
		return 0;
	if (request_restart || request_shutdown)
		return 0;
	if (kill(task->ppid, 0) == -1)
		request_shutdown = 1;

	return 0;
}

static int 
udp_parse(struct msg *msg, byte *packet, unsigned int len)
{
	struct aaa *aaa = msg->aaa;
	byte *ptr = packet, *end = packet + len;
	while (packet < end) {
		byte *key = packet;
		while (packet < end && *packet != ':' && *packet != '\n')
			packet++;
		if (packet >= end)
			return -1;
		if (*packet != ':')
			return packet - ptr;
		*packet++ = 0;
		byte *value = packet;
		while (packet < end && *packet != '\n')
			packet++;
		if (packet >= end)
			return -1;
		*packet++ = 0;

		debug3("%s:%s", key, value);

		if (!strcasecmp(key, "sess.id"))
			msg->sid = value;
		if (!strcasecmp(key, "user.id"))
			msg->uid = value;

		if (strncasecmp(key, "msg.", 4)) {
			aaa_attr_set(aaa, key, value);
			continue;
		}

		if (!strcasecmp(key, "msg.op"))
			msg->op = value;
		else if (!strcasecmp(key, "msg.id"))
			msg->id = value;
		
	}
	return len;
}

static int
attr_enc(byte *packet, int len, int mlen, char *key, char *val)
{
	if (len < 0)
		return len;

	int klen = strlen(key), vlen = strlen(val);
	int linelen = klen + 1 + vlen + 1;

	if (len + linelen > mlen)
		return -1;
	packet += len;
	memcpy(packet, key, klen);
	packet += klen;
	*packet++ = ':';
	memcpy(packet, val, vlen);
	packet += vlen;
	*packet = '\n';
	return linelen;
}

static int
udp_build(struct msg *msg, byte *pkt, int size)
{
	char *status = printfa("%d", msg->status);
	int len = 0;
	len += attr_enc(pkt, len, size, "msg.status", status);
	len += attr_enc(pkt, len, size, "msg.id", "1");
	debug3("msg.status:%s", status);
	debug3("msg.id:%s", "1");

	dict_for_each(a, msg->aaa->attrs.list) {
		debug3("%s:%s", a->key, a->val);
		len += attr_enc(pkt, len, size, a->key, a->val);
	}

	return len;
}

struct cmd {
	struct msg msg;
	const char *peer;
};

static int
cmd_nop(struct cmd *cmd)
{
	struct msg *msg = &cmd->msg;
	msg->status = 0;
	return 0;
}

static int
cmd_set(struct cmd *cmd)
{
	return 0;
}

static int
cmd_get(struct cmd *cmd)
{
	return 0;
}

static int
cmd_touch(struct cmd *cmd)
{
	struct msg *msg = &cmd->msg;
	msg->status = 0;
	return msg->sid ? session_touch(msg->aaa, msg->sid) : -EINVAL;
}

static int
cmd_bind(struct cmd *cmd)
{
	struct msg *msg = &cmd->msg;
	msg->status = 0;
	return msg->sid ? session_bind(msg->aaa, msg->sid) : -EINVAL;
}

static int
cmd_select(struct cmd *cmd)
{
	struct msg *msg = &cmd->msg;
	msg->status = 0;
	return msg->sid ? session_select(msg->aaa, msg->sid) : -EINVAL;
}

static int
cmd_commit(struct cmd *cmd)
{
	struct msg *msg = &cmd->msg;
	msg->status = 0;
	return msg->sid ? session_commit(msg->aaa, msg->sid) : -EINVAL;
}

static int
cmd_delete(struct cmd *cmd)
{
	return 0;
}

static const struct cmd_table {
	const char *name;
	int (*handler)(struct cmd *cmd);
} cmd_table[] = {
	{ "nop",    cmd_nop    },
	{ "touch",  cmd_get    },
	{ "bind",   cmd_bind   },
	{ "select", cmd_select },
	{ "commit", cmd_commit },
	{ "delete", cmd_delete },
	{ NULL,     NULL }
};

static int
cmd_execute(struct cmd *cmd, const struct cmd_table *d)
{
	d->handler(cmd);
	return 0;
}

static int
cmd_parse(struct cmd *cmd)
{
	struct msg *msg = &cmd->msg;

	if (!msg->id || !msg->op)
		return -EINVAL;

	const struct cmd_table *d = cmd_table;
	while (d->name && strcmp(msg->op, d->name))
		d++;
	if (d->handler)
		return cmd_execute(cmd, d);
	return -EINVAL;
}

static void
udp_serve(struct task *task)
{
	struct cmd cmd;
	struct msg *msg = &cmd.msg;
	msg->aaa = (struct aaa *)task_user_get(task);

	byte pkt[8192];
	struct sockaddr_in from;
	socklen_t len = sizeof(from);

	irq_enable();
	ssize_t size = recvfrom(fd, pkt, sizeof(pkt), MSG_TRUNC, &from, &len);
	irq_disable();

	if (size < 0) switch(errno) {
		case EAGAIN:
			sched_idle(task);
			return;
		case EINTR: 
			return;
		default:
			error("unexpected error reason=%s", strerror(errno));
			request_shutdown = 1;
			return;
	}

	pkt[size] = 0;

	char *v = printfa("%s:%d", inet_ntoa(from.sin_addr), ntohs(from.sin_port));
	debug2("%s recv %jd byte(s)", v, (intmax_t)size);

	if (udp_parse(msg, pkt, (int)size) < 0)
		goto cleanup;

	if (cmd_parse(&cmd))
		goto cleanup;

	if ((size = udp_build(msg, pkt, sizeof(pkt) - 1)) < 1)
		goto cleanup;

	pkt[size] = 0;
	int sent = sendto(fd, pkt, size, 0, &from, len);
	debug2("%s sent %d byte(s)", v, sent);

	if (sent < 0)
	        error("sendto failed: reason=%s ", strerror(errno));
	else if (sent < size)
		error("sendto sent partial packet (%d of %d bytes)", sent, (int)size);

cleanup:
	aaa_reset(msg->aaa);
}

const char *
task_gettypename(struct task *task)
{
	return task_type_names[task->type];
}

const char *
task_getstatename(struct task *task)
{
	return task_state_names[task->state];
}

int
task_getid(struct task *task)
{
	switch (task->type) {
	case TASK_TYPE_DISP:
		return getpid();
	default:
		return -1;
	}
}

/*
static inline void
sched_info(struct task *task)
{
	const char *type = task_gettypename(task);
	const char *state = task_getstatename(task);
	debug("index=%.2d state=%s type=%s", task->index, state, type);
}
*/

/*
int
sched_state(struct task *task,  enum task_state state)
{

}
*/

void
task_init(struct task *task)
{
	node_init(&task->node);
	list_init(&task->list);
	task->state = TASK_STATE_INIT;

	if (task == &task_disp)
		task->type = TASK_TYPE_DISP;
	else
		task->type = TASK_TYPE_WORK;

	switch (task->type) {
	case TASK_TYPE_DISP:
		task->ppid = task->pid = getpid();
		task->loop = ev_default_loop(0);
		signal_norace(task);
		ev_timer_init(&task->timer_watcher, timer, 5, 0.);
		ev_timer_start(task->loop, &task->timer_watcher);  
		/* setup signal handlers */
		ev_signal_init(&task->sigint_watcher,  sighandler, SIGINT);
		ev_signal_init(&task->sigterm_watcher, sighandler, SIGTERM);
		ev_signal_init(&task->sighup_watcher,  sighandler, SIGHUP);
		ev_signal_init(&task->sigusr1_watcher,  sighandler, SIGUSR1);
		ev_signal_start(task->loop, &task->sigint_watcher);
		ev_signal_start(task->loop, &task->sigterm_watcher);
		ev_signal_start(task->loop, &task->sighup_watcher);
		ev_signal_start(task->loop, &task->sigusr1_watcher);
		setproctitle("aaad");
		sig_enable(SIGTERM);
		sig_enable(SIGINT);
		sig_enable(SIGCHLD);
		sig_enable(SIGUSR1);
		break;
	case TASK_TYPE_WORK:
		setproctitle("aaad-worker");
		sig_action(SIGHUP, huphandler);
		sig_disable(SIGTERM);
		sig_disable(SIGINT);
		sig_disable(SIGUSR1);
		sig_disable(SIGUSR2);
		sig_ignore(SIGINT);
		sig_ignore(SIGTERM);
		struct aaa *aaa = aaa_new(AAA_ENDPOINT_SERVER, 0);
		task_user_set(task, aaa);
		break;
	default:
		die("unexpected task type");
		break;
	}
	const char *type = task_gettypename(task);
	const char *state = task_getstatename(task);
	int cpu = sched_getcpu();
	info("process started index=%.2d cpu=%d state=%s type=%s", 
	     task->pid == task->ppid ? 0: task->index, cpu, state, type);
}

int
task_wait(struct task *task);

void
task_fini(struct task *task);

static inline void
sched_pdeathsig(struct task *task)
{
	/*
	if (prctl(PR_SET_PDEATHSIG, SIGHUP) < 0)
		die("prctl reason=%s", strerror(errno));
	debug4("prctl type=PR_SET_PDEATHSIG sig=SIGHUP");
	*/
}

static void
sched(struct task *task)
{                                                                               
	pid_t pid;
	while (task->running < task->workers && !request_shutdown) {
		debug4("workers=%d running=%d", task->workers, task->running);
		struct task *child = NULL;
		int spawned = 1;
		list_for_each_item(task->list, child, node) {
			if (child->state != TASK_STATE_NONE)
				continue;
			spawned = 0;
			goto init;

		}

		child = malloc(sizeof(*child));
		memset(child, 0, sizeof(*child));
		task->index++;
		child->index = task->index;
init:
		child->type  = TASK_TYPE_WORK;
		child->state = TASK_STATE_INIT; 
		child->version = task->version;
		child->ppid = task->pid;

		pid = fork();
		if (pid == 0) {
			ev_loop_fork(EV_DEFAULT);
			task_init(child);
			sig_enable(SIGHUP);
			task_wait(child);
			task_fini(child);
			exit(0);
		}

		ev_child_init(&child->child_watcher, chld_handler, pid, 1);
		ev_child_start(EV_DEFAULT_ &child->child_watcher);
		task->running++;
		child->pid = pid; 
		if (!spawned)
			continue;

		list_add(&task->list, &child->node);	
	}
}

void
task_fini(struct task *task)
{
	struct task *child;
	list_for_each_item(task->list, child, node) {
		kill(child->pid, SIGHUP);
		int status = 0;
		debug3("waiting for the subprocess pid=%d", child->pid);
		int rv = waitpid(child->pid, &status, 0);
		if (rv == -1)
			die("waitpid() failed reason=%s", strerror(errno));

	};

	struct aaa *aaa;
	switch (task->type) {
	case TASK_TYPE_DISP:
		break;
	case TASK_TYPE_WORK:
		aaa = (struct aaa *)task_user_get(task);
		aaa_free(aaa);
		break;
	default:
		die("task type broken");
		break;
	}
	
	const char *type = task_gettypename(task);
	const char *state = task_getstatename(task);
	int cpu = sched_getcpu();
	info("process stopped index=%.2d cpu=%d state=%s type=%s", 
	      task->pid == task->ppid ? 0: task->index, cpu, state, type);
}

int
task_wait(struct task *task)
{
	task->state = TASK_STATE_WORK;

	switch (task->type) {
	case TASK_TYPE_DISP:
		sched(task);
		ev_loop(task->loop, 0);
		break;
	case TASK_TYPE_WORK:
		while(!request_restart && !request_shutdown) {
			udp_serve(task);
		}
		task_fini(task);
		exit(0);
	default:
		die("unknown task type");
		break;
		
	}
	return 0;
}

struct sched_class {
	unsigned int per_cpu_proc;
	unsigned int per_cpu_thread;
	unsigned int workers;
};

static void
configure(void)
{
	info("configuring from ~/.aaa/");
	/* configure etc */
	request_restart = 0;
	timestamp_t now = get_timestamp();
	task_disp.version = now;

}

static void
restart(void)
{
	configure();
	struct task *child;
	list_for_each_item(task_disp.list, child, node)
		kill(child->pid, SIGHUP);
}

void
sched_init(void)
{
	task_init(&task_disp);
	task_disp.workers = 4;
	info("started");
	udp_init();

	configure();
	debug("udp port=%d", port);
}

void
sched_wait(void)
{
	do {
		if (request_shutdown)
			break;
		if (request_restart)
			restart();

		task_wait(&task_disp);
	} while(1);

}

void
sched_fini(void)
{
	task_fini(&task_disp);
	info("stopped");
}

int
aaa_server1(int argc, char *argv[])
{
	irq_init();
	irq_disable();
	session_init();
	setproctitle_init(argc, argv);

	_unused struct sched_class sched_class = {
		.per_cpu_proc    = 1,
		.per_cpu_thread  = 1,
		.workers         = 1
	};

	sched_init();
	sched_wait();
	sched_fini();

	session_fini();
	return 0;
}

__attribute__((constructor)) 
static void aaa_server_ctor(void) { aaa_server = aaa_server1; }
