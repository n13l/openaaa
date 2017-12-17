
#include <sys/compiler.h>
#include <signal.h>
#include <sys/log.h>
#include <sys/irq.h>
#include <sys/mpm.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <buffer.h>

#ifdef CONFIG_LINUX
/* workarround missing types */
#define __u64 u64
#define __u32 u32
#define __u16 u16
#include <linux/types.h>
#include <sys/prctl.h>
#endif

#include <mem/stack.h>
#include <net/proto.h>
#include <list.h>
#include <copt/lib.h>
#include <unix/timespec.h>

#ifndef WIN32
#include <sys/ev/model.h>
#include <sys/ev/ev.c>
#endif

static sig_atomic_t request_shutdown = 0;
static sig_atomic_t request_restart  = 0;
static sig_atomic_t request_info     = 0;

#ifndef CONFIG_WIN32
/* processes or per_cpu should not be set together */
int max_process = 8;
int max_threads = 8;
int max_workers = 6;
int max_runjobs = 2;
int max_quejobs = 8;

int job_parallel    = 2;
int max_job_queue   = 4;
int per_cpu_proc    = 2;
int per_cpu_threads = 2;

int timeout_job          = 1800; /* 30 minutes maximum for any job */
int timeout_killable     = 5;    /* timeout for gracefull shutdown */
int timeout_interuptible = 5;

int (*ctor_task)(struct task *) = NULL;
int (*dtor_task)(struct task *) = NULL;
int (*main_task)(struct task *) = NULL;

struct mpm_workqueue {
	struct list run;
	struct list que;
	sig_atomic_t running;
	sig_atomic_t waiting;
} workque = { .running = 0, .waiting = 0};

struct mpm_workers {
	struct list list;
	sig_atomic_t running;
	sig_atomic_t total;
} workers = { .running = 0, .total = 0};

struct process_time {
	timestamp_t created;
	timestamp_t expires;
	timestamp_t exited;
};

struct process_status {
	u32 id;
	u32 hash;
	u16 type;
};

struct process_ev {
	struct ev_loop *loop;
	struct ev_timer timer;
	struct ev_idle *idle;
	struct ev_prepare prepare;
	struct ev_check check;
	struct ev_signal sigs[32];
	struct ev_child child;
	struct ev_io ipc;
};

struct process {
	struct node node;
	struct node queued;
	struct process_time time;
	struct process_ev ev;
	struct task self;
	int caps;
	int type;
	int ipc[2];
};

enum ipc_type {
	IPC_WORKQUE_ADD   = 1,
	IPC_WORKQUE_DEL   = 2,
	IPC_STATUS        = 3,
	IPC_CUSTOM        = 4,
};

enum ipc_dir {
	IPC_REQUEST       = 1,
	IPC_RESPONSE      = 2
};

static const char *s_ipc_msg[] = {
	[IPC_WORKQUE_ADD] = "workque-add",
	[IPC_WORKQUE_DEL] = "workque-del",
	[IPC_STATUS]      = "status",
	[IPC_CUSTOM]      = "custom",
};

static const char *s_ipc_dir[] = {
	[IPC_REQUEST]     = "request",
	[IPC_RESPONSE]    = "response"
};

struct ipc_msg {
	u16 type; u16 dir; u32 mid; u32 sid; u32 did; u32 size;
};

struct process root;

static void
chld_handler(EV_P_ ev_child *w, int revents);

static void
do_balance(struct process *task);

static void
process_exited(int pid, int status)
{
	info("process pid: %d exited, status: %d", pid, WEXITSTATUS(status));
}

static void
process_signaled(int pid, int status)
{
	info("process pid: %d killed by signal %d (%s)", 
	     pid, WTERMSIG(status), strsignal(WTERMSIG(status)));
}

static void
process_stopped(int pid, int status)
{
	info("process pid: %d stopped by signal %d", pid, WSTOPSIG(status));
}

static void
process_continued(int pid, int status)
{
	info("process pid: %d continued", pid);
}

static int
process_status(int pid, int status)
{
	if (WIFEXITED(status))
		process_exited(pid, status);
	else if (WIFSIGNALED(status))
		process_signaled(pid, status);
	else if (WIFSTOPPED(status))
		process_stopped(pid, status);
	else if (WIFCONTINUED(status))
		process_continued(pid, status);

	return status;
}

int
subprocess_wait(pid_t pid, int secs)
{
	info("waiting for the process pid: %d", pid);
	int v, status;
	for (v = 0; v == 0 && secs > 0; secs--) {
		if ((v = waitpid(pid, &status, WNOHANG)) == -1)
			error("wait() reason=%s", strerror(errno));
		else if (v == 0)
			sleep(1);
		else 
			return process_status(pid, status);
	}

	info("process pid: %d did not respond within the timeframe", pid);
	kill(pid, SIGKILL);
	info("process pid: %d killed by signal %d", pid, 9);
	return v;
}

static inline struct process *
subprocess_alloc(void)
{
	struct process *proc = malloc(sizeof(*proc));
	memset(proc, 0, sizeof(*proc));

	proc->self.state = TASK_INACTIVE;
	proc->self.created = get_timestamp();

	node_init(&proc->node);
	node_init(&proc->queued);
	return proc;
}

static u32 id_counter = 1;

int
sched_workque_add(void)
{
	if (workque.waiting > max_job_queue)
		return -1;

	struct process *proc = subprocess_alloc();
	if (id_counter > 8192)
		id_counter = 0;

	proc->self.id = id_counter++;
	proc->type = TASK_WORKQUE;
	list_add(&workque.que, &proc->queued);
	workque.waiting++;
	return proc->self.id;
}

int
sched_workque_del(void)
{
	return -1;
}

static void
ipc_handler(EV_P_ struct ev_io *w, int revents)
{
	if (!(revents & EV_READ))
		return;

	char buffer[8192] = {0};
	int rv = read(w->fd, buffer, sizeof(buffer));
	if (rv < 0) {
		error("result=%d %d:%s", rv, errno, strerror(errno));
		return;
	} else if (rv == 0) {
		error("ipc disconnected");
		return;
	}

	buffer[rv] = 0;
	struct ipc_msg *req = (struct ipc_msg *)buffer;
	if (rv < sizeof(*req)) {
		error("ipc msg malformed");
		return;
	}

	debug3("ipc msg recv %s:%s", 
	       s_ipc_msg[req->type], s_ipc_dir[req->dir]);
	switch (req->type) {
	case IPC_WORKQUE_ADD: {
		int id = sched_workque_add();
		struct ipc_msg res = { 
			.type = IPC_WORKQUE_ADD, .dir  = IPC_RESPONSE, 
			.size = sizeof(res), .sid  = id
		};

		debug3("ipc msg send %s:%s", 
		       s_ipc_msg[res.type], s_ipc_dir[res.dir]);
		if ((rv = write(w->fd, &res, res.size)) < res.size)
			error("result=%d %d:%s", rv, errno, strerror(errno));

		ev_break(loop, EVBREAK_ALL);
	}
	break;
	}
}

int
sched_workque(struct task *proc, const char *arg)
{
	struct process *p = __container_of(proc, struct process, self);

	struct ipc_msg msg = { 
		.type = IPC_WORKQUE_ADD, .dir = IPC_REQUEST, .size = sizeof(msg)
	};

	debug3("ipc msg send %s:%s", s_ipc_msg[msg.type], s_ipc_dir[msg.dir]);

	int rv;
	if ((rv = write(p->ipc[1], &msg, msg.size)) < msg.size)
		goto error;
	if ((rv = read(p->ipc[1], &msg, sizeof(msg))) < sizeof(msg))
		goto error;

	debug3("ipc msg recv %s:%s", s_ipc_msg[msg.type], s_ipc_dir[msg.dir]);
	return msg.sid;

error:
	error("%d:%s", errno, strerror(errno));
	return -1;	
}

static inline void
subprocess_attach(struct process *proc)
{
	ev_child_init(&proc->ev.child, chld_handler, proc->self.pid, 1);
	ev_child_start(EV_DEFAULT_ &proc->ev.child);

	ev_io_init(&proc->ev.ipc, ipc_handler,  proc->ipc[0], EV_READ);
	ev_io_start(EV_DEFAULT_ &proc->ev.ipc);
}

static inline void
subprocess_detach(struct process *proc)
{
	proc->self.state = TASK_INACTIVE;

	ev_child_stop(EV_DEFAULT_ &proc->ev.child);
	ev_io_stop(EV_DEFAULT_ &proc->ev.ipc);
	close(proc->ipc[0]);
	close(proc->ipc[1]);
}

static void
sig_handler(struct ev_loop *loop, ev_signal *w, int revents)
{
	if (w->signum == SIGINT)
		write(1, "\n", 1);

	debug3("%s (%d) processed", strsignal(w->signum), w->signum);
	if (w->signum == SIGTERM || w->signum == SIGINT)
		request_shutdown = 1;
	if (w->signum == SIGHUP)
		request_restart = 1;
	if (w->signum == SIGUSR1) {
		request_info = 1;
		info("workers=%d running=%d", workers.total, workers.running);
		info("workque=%d running=%d", workque.waiting, workque.running);
	}

	if (w->signum == SIGSEGV) {
		signal(w->signum, SIG_DFL);
		kill(getpid(), w->signum);
	}

	ev_break(loop, EVBREAK_ALL);
}

static void
chld_handler(EV_P_ ev_child *w, int revents)
{
	process_status(w->rpid, w->rstatus);
	struct process *c;
	list_for_each_item(workers.list, c, node) {
		if (w->rpid != c->self.pid)
			continue;
		if (WIFEXITED(w->rstatus) || WIFSIGNALED(w->rstatus)) {
			workers.running--;
			subprocess_detach(c);
		}
	}

	list_for_each_delsafe(workque.run, node) {
		c = __container_of(node, struct process, queued);
		if (w->rpid != c->self.pid)
			continue;
		if (WIFEXITED(w->rstatus) || WIFSIGNALED(w->rstatus)) {
			workque.running--;
			subprocess_detach(c);
			list_del(&c->queued);
		}
	}

	ev_break(loop, EVBREAK_ALL);
}

static void
hup_handler(int signo, siginfo_t *info, void *context)
{
	debug3("%s (%d) processed", strsignal(signo), signo);
	request_restart = 1;
}

static void
timer(EV_P_ ev_timer *w, int revents)
{
}

static void
idle(struct ev_loop *loop, ev_idle *w, int revents)
{
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

static void
signal_norace(struct process *task)
{
	struct process_ev *c = &task->ev;
	ev_prepare_init(&c->prepare, prepare);
	ev_prepare_start(c->loop, &c->prepare);
	ev_check_init(&c->check, check);
	ev_check_start(c->loop, &c->check);
}

static void
do_restart(void)
{
	request_restart = 0;
	root.self.version = get_timestamp();

	struct process *c;
	list_for_each_item(workers.list, c, node) {
		kill(c->self.pid, SIGHUP);
		int status = subprocess_wait(c->self.pid, timeout_killable);
		if (WIFEXITED(status) || WIFSIGNALED(status)) {
			workers.running--;
			subprocess_detach(c);
		}
	}
}

static void
do_shutdown(void)
{
	struct process *c;
	list_for_each_item(workers.list, c, node) {
		kill(c->self.pid, SIGHUP);
		subprocess_wait(c->self.pid, timeout_killable);
		workers.running--;
		subprocess_detach(c);
	}

	list_for_each_item(workque.run, c, queued) {
		kill(c->self.pid, SIGHUP);
		subprocess_wait(c->self.pid, timeout_killable);
		workque.running--;
		subprocess_detach(c);
	}
}

static void
do_ctor_disp(struct process *task)
{
	struct process_ev *c = &task->ev;
	task->self.ppid = task->self.pid = getpid();

	c->loop = ev_default_loop(0);
	signal_norace(task);

	ev_timer_init(&c->timer, timer, timeout_interuptible, 0.);
	ev_timer_start(c->loop, &c->timer);  

	ev_signal_init(&c->sigs[SIGINT],  sig_handler, SIGINT);
	ev_signal_init(&c->sigs[SIGTERM], sig_handler, SIGTERM);
	ev_signal_init(&c->sigs[SIGHUP],  sig_handler, SIGHUP);
	ev_signal_init(&c->sigs[SIGUSR1], sig_handler, SIGUSR1);
	ev_signal_start(c->loop, &c->sigs[SIGINT]);
	ev_signal_start(c->loop, &c->sigs[SIGTERM]);
	ev_signal_start(c->loop, &c->sigs[SIGHUP]);
	ev_signal_start(c->loop, &c->sigs[SIGUSR1]);

	sig_enable(SIGTERM);
	sig_enable(SIGINT);
	sig_enable(SIGHUP);
	sig_enable(SIGCHLD);
	sig_enable(SIGUSR1);
}

static void
do_ctor_proc(struct process *task)
{
	sig_action(SIGHUP, hup_handler);
	sig_disable(SIGTERM);
	sig_disable(SIGINT);
	sig_disable(SIGUSR1);
	sig_disable(SIGUSR2);
	sig_ignore(SIGINT);
	sig_ignore(SIGTERM);

	task->self.pid = getpid();
	ctor_task(&task->self);
}

static void
do_ctor(struct process *task)
{
	task->self.state = TASK_INACTIVE;
	if (task == &root) {
		node_init(&task->node);

		do_ctor_disp(task);
	}
	else
		do_ctor_proc(task);
}

static void
do_dtor(struct process *proc)
{
	if (proc == &root) 
		goto exit;

	dtor_task(&proc->self);
	close(proc->ipc[0]);
	close(proc->ipc[1]);
exit:	
	debug3("process pid: %d exiting", proc->self.pid);
	return;
}

int
do_wait(struct process *proc)
{
	struct task *task = &proc->self;
	struct process_ev *c = &proc->ev;
	task->state = TASK_RUNNING;

	if (proc == &root) {
		do_balance(proc);
		ev_loop(c->loop, 0);
	} else {	
		while(!request_restart && !request_shutdown) {
			if (main_task)
				main_task(task);
		}
		do_dtor(proc);
		exit(0);
	}
	return 0;
}

static inline struct process *
do_subprocess_alloc(struct process *root)
{
	struct process *proc = malloc(sizeof(*proc));
	memset(proc, 0, sizeof(*proc));

	proc->self.state = TASK_INACTIVE;
	proc->self.index = ++root->self.index;
	proc->self.created = get_timestamp();

	node_init(&proc->node);
	node_init(&proc->queued);

	return proc;
}

/* subprocess constructor running in parent context yet */
static inline void
do_subprocess_ctor(struct process *root, struct process *proc)
{
	struct task *t1 = &root->self;
	struct task *t2 = &proc->self;

	t2->version  = t1->version;
	t2->ppid     = t1->pid;
	t2->state    = TASK_RUNNING;

	if (socketpair(PF_UNIX, SOCK_STREAM, 0, proc->ipc))
		error("Can not create ipc anonymous unix socket");

}

/* subprocess destructor running in parent context yet */
static inline void
do_subprocess_dtor(struct process *proc)
{
}

static inline void
do_subprocess(struct process *proc)
{
	struct task *task = &proc->self;
	task->pid = getpid();

	close(proc->ipc[0]);
	ev_loop_fork(EV_DEFAULT);

#ifdef CONFIG_LINUX
	if (!prctl(PR_SET_PDEATHSIG, SIGHUP))
		proc->caps |= TASK_PDEATHSIGHUP;
	/* avoid race between parent death and prctl() */
	if (kill(proc->self.ppid, 0))
		request_shutdown = request_restart = 1;
#endif
	do_ctor(proc);
	sig_enable(SIGHUP);
	do_wait(proc);
	do_dtor(proc);
	close(proc->ipc[1]);
	exit(0);
}

static inline void
do_workque(struct process *proc)
{
	struct task *task = &proc->self;
	task->pid = getpid();

	close(proc->ipc[0]);
	ev_loop_fork(EV_DEFAULT);

#ifdef CONFIG_LINUX
	if (!prctl(PR_SET_PDEATHSIG, SIGHUP))
		proc->caps |= TASK_PDEATHSIGHUP;
	/* avoid race between parent death and prctl() */
	if (kill(proc->self.ppid, 0))
		request_shutdown = request_restart = 1;
#endif
	sig_enable(SIGHUP);
	do_ctor(proc);
	info("workque process");
	sleep(5);
	do_dtor(proc);
	close(proc->ipc[1]);
	exit(0);
}


static struct process *
get_inactive_subprocess(struct process *root)
{
	struct process *proc = NULL;
	list_for_each_item(workers.list, proc, node) {
		if (proc->self.state != TASK_INACTIVE)
			continue;
		return proc;
	}

	proc = do_subprocess_alloc(root);
	list_add(&workers.list, &proc->node);	
	return proc;
}

static inline void
do_subprocess_fail(struct process *proc)
{
	proc->self.state = TASK_INACTIVE;
	error("Can not fork()");
	sleep(1);
}

static void
do_balance(struct process *root)
{
	while ((workers.running < workers.total) && !request_shutdown) {
		struct process *proc = get_inactive_subprocess(root);
		do_subprocess_ctor(root, proc);

		proc->self.pid = fork();
		if (proc->self.pid == 0)
			do_subprocess(proc);
		else if (proc->self.pid < 0) {
			do_subprocess_fail(proc);
			continue;
		} else {

		subprocess_attach(proc);
		proc->self.state = TASK_RUNNING;
		workers.running++;
		}
	}

	while(workque.waiting > 0 && (workque.running < job_parallel)) {
		struct node *node = list_first(&workque.que);
		struct process *proc = __container_of(node, struct process, queued);
		do_subprocess_ctor(root, proc);

		proc->self.pid = fork();
		if (proc->self.pid == 0)
			do_workque(proc);
		else if (proc->self.pid < 0) {
			do_subprocess_fail(proc);
			continue;
		}

		subprocess_attach(proc);
		proc->self.state = TASK_RUNNING;

		workque.running++;
		workque.waiting--;

		list_del(&proc->queued);
		node_init(&proc->queued);
		list_add(&workque.run, &proc->queued);
	}

	debug4("workers running=%d total=%d workque running=%d waiting=%d", 
	     workers.running, workers.total, workque.running, workque.waiting);
}

void
sched_timeout_interuptible(int timeout)
{
}

void
sched_timeout_uninteruptible(int timeout)
{
}

void
sched_timeout_killable(int timeout)
{
}

void
sched_timeout_throttled(int timeout)
{
}

void sched_info_show(void)
{
}

void
_sched_start(const struct mpm_module *mpm_module)
{
	list_init(&workers.list);
	list_init(&workque.run);
	list_init(&workque.que);

	const struct sched_params *params = mpm_module->sched_params;
	if ((params->max_processes - params->max_job_parallel) < 1 )
		die("increase max_processes parameter");

	workers.total = params->max_processes - params->max_job_parallel;
	do_ctor(&root);

	debug3("scheduler limits  processes: %d (workers: %d, job_parallel: %d) queue: %d", 
		params->max_processes, workers.total, 
		params->max_job_parallel, params->max_job_queue);
	debug3("scheduler timeout interuptible: %d, killable: %d, throttled: %d, status: %d",
	       params->timeout_interuptible, params->timeout_killable,
	       params->timeout_throttled, params->timeout_status);

	debug1("status cache hash table entries: %d (order: %d, %d bytes)", 0, 0, 0);
}

void
_sched_wait(const struct mpm_module *mpm_module)
{
	while (!request_shutdown) {
		do_wait(&root);
		if (request_restart)
			do_restart();
	}
}

void
_sched_stop(const struct mpm_module *mpm_module)
{
	do_shutdown();
	do_dtor(&root);
}
#else
void
_sched_start(const struct mpm_module *mpm_module)
{
}

void
_sched_wait(const struct mpm_module *mpm_module)
{
}

void
_sched_stop(const struct mpm_module *mpm_module)
{
}

#endif
