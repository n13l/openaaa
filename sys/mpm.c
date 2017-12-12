#include <sys/compiler.h>
#include <signal.h>
#include <sys/log.h>
#include <sys/irq.h>
#include <sys/mpm.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <mem/stack.h>
#include <net/proto.h>
#include <list.h>
#include <copt/lib.h>

#include <unix/timespec.h>
	
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

#ifndef WIN32
#include <sys/ev/ev.c>
#endif

_unused static sig_atomic_t request_shutdown = 0;
_unused static sig_atomic_t request_restart  = 0;
_unused static sig_atomic_t request_info     = 0;

/* processes or per_cpu should not be set together */
int max_process = 8;
int max_threads = 8;
int max_workers = 6;
int max_runjobs = 2;
int max_quejobs = 8;

int job_parallel = 2;
int job_queued   = 8;

int per_cpu_proc    = 2;
int per_cpu_threads = 2;

int timeout_job      = 1800; /* 30 minutes maximum for any job */
int timeout_killable = 15;   /* timeout for gracefull shutdown */

int (*ctor_task)(struct task *) = NULL;
int (*dtor_task)(struct task *) = NULL;
int (*main_task)(struct task *) = NULL;

struct mpm_workqueue {
	struct list running;
	struct list queued;
};

struct mpm_task_node {
	struct node node;
	struct list list;
	unsigned int running;
	unsigned int total;
};

struct mpm_task_time {
	timestamp_t created;
	timestamp_t expires;
	timestamp_t exited;
};

struct mpm_task_libev {
	struct ev_loop *loop;
	struct ev_timer timer;
	struct ev_idle *idle;
	struct ev_prepare prepare;
	struct ev_check check;
	struct ev_signal sigs[32];
	struct ev_child child;
};

struct mpm_task {
	struct node node;
	struct list list;
	unsigned int running;
	unsigned int total;
	struct mpm_task_time time;
	struct mpm_task_libev libev;
	struct task self;
	int type;
};

struct mpm_task task_disp;

static void
do_balance(struct mpm_task *task);

static void
process_exited(int pid, int status)
{
	info("process pid=%d exited, status=%d", pid, WEXITSTATUS(status));
}

static void
process_signaled(int pid, int status)
{
	info("process pid=%d killed by signal %d (%s)", 
	     pid, WTERMSIG(status), strsignal(WTERMSIG(status)));
}

static void
process_stopped(int pid, int status)
{
	info("process pid=%d stopped by signal %d", pid, WSTOPSIG(status));
}

static void
process_continued(int pid, int status)
{
	info("process pid=%d continued", pid);
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
process_wait(pid_t pid, int secs)
{
	debug1("waiting for the process pid=%d (timeout: %d secs)", pid, secs);
	for (int status, v;;) {
		for (v = 0; v == 0 && secs > 0; secs--) {
			if ((v = waitpid(pid, &status, WNOHANG)) == -1)
				error("wait() reason=%s", strerror(errno));
			else if (v == 0)
				sleep(1);
			else 
				return process_status(pid, status);
		}

		info("process pid=%d did not respond within " 
		     "the expected timeframe", pid);
		kill(pid, SIGKILL);
	} 

	return -1;
}

static void
sig_handler(struct ev_loop *loop, ev_signal *w, int revents)
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
		info("workers=%d running=%d", task_disp.total, task_disp.running);
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
	if ((WIFEXITED(w->rstatus)) || (WIFSIGNALED(w->rstatus)))
		ev_child_stop (EV_A_ w);

	process_status(w->rpid, w->rstatus);
	struct mpm_task *c;
	list_for_each_item(task_disp.list, c, node) {
		if (w->rpid != c->self.pid)
			continue;
		if (WIFEXITED(w->rstatus) || WIFSIGNALED(w->rstatus)) {
			task_disp.running--;
			c->self.state = TASK_INACTIVE;
		}
	}

	ev_break(loop, EVBREAK_ALL);
}

static void
hup_handler(int signo, siginfo_t *info, void *context)
{
	debug3("signum=%d reason=%s processed", signo, strsignal(signo));
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
signal_norace(struct mpm_task *task)
{
	struct mpm_task_libev *c = &task->libev;
	ev_prepare_init(&c->prepare, prepare);
	ev_prepare_start(c->loop, &c->prepare);
	ev_check_init(&c->check, check);
	ev_check_start(c->loop, &c->check);
}

static void
do_restart(void)
{
	request_restart = 0;
	task_disp.self.version = get_timestamp();

	struct mpm_task *c;
	list_for_each_item(task_disp.list, c, node) {
		kill(c->self.pid, SIGHUP);
		int status = process_wait(c->self.pid, timeout_killable);
		if (WIFEXITED(status) || WIFSIGNALED(status)) {
			task_disp.running--;
			c->self.state = TASK_INACTIVE;
		}
	}
}

static void
do_shutdown(void)
{
	struct mpm_task *c;
	list_for_each_item(task_disp.list, c, node) {
		kill(c->self.pid, SIGHUP);
		process_wait(c->self.pid, timeout_killable);
		c->self.state = TASK_EXITING;
		task_disp.running--;
	}
}

static void
do_ctor_disp(struct mpm_task *task)
{
	struct mpm_task_libev *c = &task->libev;
	task->self.ppid = task->self.pid = getpid();

	c->loop = ev_default_loop(0);
	signal_norace(task);

	ev_timer_init(&c->timer, timer, 5, 0.);
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
	sig_enable(SIGCHLD);
	sig_enable(SIGUSR1);
}

static void
do_ctor_proc(struct mpm_task *task)
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
do_ctor(struct mpm_task *task)
{
	node_init(&task->node);
	list_init(&task->list);

	task->self.state = TASK_INACTIVE;
	task->type = task == &task_disp ? TASK_TYPE_DISP: TASK_TYPE_PROC;

	if (task == &task_disp)
		do_ctor_disp(task);
	else
		do_ctor_proc(task);
}

static void
do_dtor(struct mpm_task *proc)
{
	struct task *task = &proc->self;

	if (proc!= &task_disp)
		dtor_task(task);

	close(task->ipc[0]);
	close(task->ipc[1]);
}

int
do_wait(struct mpm_task *proc)
{
	struct task *task = &proc->self;

	struct mpm_task_libev *c = &proc->libev;
	task->state = TASK_RUNNING;

	if (proc == &task_disp) {
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

static inline void
do_process_init(struct mpm_task *parent, struct mpm_task *proc)
{
	struct task *t1 = &parent->self;
	struct task *t2 = &proc->self;

	node_init(&proc->node);
	list_init(&proc->list);

	proc->type  = TASK_TYPE_PROC;
	t2->version = t1->version;
	t2->ppid    = t1->pid;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, proc->self.ipc))
		error("Can not create ipc anonymous unix socket");

	debug2("ipc %d:%d", proc->self.ipc[0], proc->self.ipc[1]);

	t2->state   = TASK_RUNNING;
}

static inline void
do_process(struct mpm_task *proc)
{
	struct task *task = &proc->self;
	task->pid = getpid();

	proc->self.state = TASK_RUNNING;

	ev_loop_fork(EV_DEFAULT);
	do_ctor(proc);
	sig_enable(SIGHUP);
	do_wait(proc);
	do_dtor(proc);
	exit(0);
}

static void
do_balance(struct mpm_task *task)
{                                                                               
	pid_t pid;
	while (task->running < task->total && !request_shutdown) {
		struct mpm_task *child = NULL;
		int spawned = 1;
		list_for_each_item(task->list, child, node) {
			if (child->self.state != TASK_INACTIVE)
				continue;
			spawned = 0;
			goto init;
		}

		child = malloc(sizeof(*child));
		memset(child, 0, sizeof(*child));
		child->self.state = TASK_INACTIVE;
		task->self.index++;
		child->self.index = task->self.index;
init:
		do_process_init(task, child);

		pid = fork();
		if (pid == 0)
			do_process(child);
		else if (pid < 0)
			die("Can not fork()");

		struct mpm_task_libev *c = &task->libev;

		ev_child_init(&c->child, chld_handler, pid, 1);
		ev_child_start(EV_DEFAULT_ &c->child);

		task->running++;
		child->self.pid = pid; 
		if (!spawned)
			continue;

		list_add(&task->list, &child->node);	
	}
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
_sched_init(void)
{
	do_ctor(&task_disp);
	task_disp.total = 2;
}

void
_sched_wait(void)
{
	while (!request_shutdown)
		do_wait(&task_disp);
}

void
_sched_fini(void)
{
	do_shutdown();
	do_dtor(&task_disp);
}
