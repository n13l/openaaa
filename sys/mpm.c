
#include <sys/compiler.h>
#include <sys/log.h>
#include <mem/alloc.h>
#include <mem/page.h>
#include <mem/pool.h>
#include <mem/map.h>

#include <signal.h>
#include <sys/log.h>
#include <sys/irq.h>
#include <sys/mpm.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <buffer.h>
#include <list.h>
#include <hash.h>

#ifdef CONFIG_LINUX
/* workarround missing types */
#define __u64 u64
#define __u32 u32
#define __u16 u16
#include <linux/types.h>
#include <sys/prctl.h>
#endif

#include <net/proto.h>
#include <copt/lib.h>
#include <unix/timespec.h>

#ifndef WIN32
#include <sys/ev/model.h>
#include <sys/ev/ev.c>
#endif

DEFINE_HASHTABLE(hstatus_id,  7);
DEFINE_HASHTABLE(hstatus_pid, 7);

struct pstatus {
	struct page page;
	time_t created;
	time_t modified;
	time_t expires;
	u32 hash_id;
	u32 hash_pid;
	pid_t id, pid;
	struct {
		struct hnode id;
		struct hnode pid;
	} n;
	struct task_status self; 
	int size;                 /* size of payload + sizeof(pstatus) */
	byte payload[];
};

static const char * const task_state_names[] = {
	[TASK_INACTIVE]   = "inactive",
	[TASK_STOPPED]    = "stopped",
	[TASK_RUNNING]    = "running",
	[TASK_EXITING]    = "exiting",
	[TASK_FINISHED]   = "finished",
};

const char *
task_sget_state(u8 id)
{
	if (id > (u8)array_size(task_state_names))
		return "undefined";
	return task_state_names[id];
}


static struct pagemap *pagemap;

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

static const struct sched_callbacks *callback;
static const struct sched_params *params;

struct workqueue {
	struct list run;
	struct list que;
	sig_atomic_t running;
	sig_atomic_t waiting;
} workque = { .running = 0, .waiting = 0};

struct workers {
	struct list list;
	sig_atomic_t running;
	sig_atomic_t total;
} workers = { .running = 0, .total = 0};

struct timeframe {
	timestamp_t created;
	timestamp_t modified;
	timestamp_t expire;
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
	struct timeframe time;
	struct process_ev ev;
	struct task self;
	char *arg;
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
	int type; int dir; int mid; int sid; int did; unsigned int size;
};

struct process root;

static time_t
secs_now(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv.tv_sec;
}

static u32 
getid(void) 
{
	static u32 id_counter = 0;
	if (id_counter > 8192)
		id_counter = 0;
	return ++id_counter;
};

int
task_is_workque(struct task *proc)
{
	struct process *p = __container_of(proc, struct process, self);

	if (p->type & TASK_WORKQUE)
		return 1;
	return 0;
}

const char *
task_arg(struct task *proc)
{
	struct process *p = __container_of(proc, struct process, self);
	return p->arg;
}

static void
pstatus_info(struct pstatus *p);

static struct pstatus *
pstatus_lookup_id(pid_t id);

static void
chld_handler(EV_P_ ev_child *w, int revents);

static void
do_balance(struct process *task);

static void
process_exited(int pid, int status)
{
	debug1("process pid: %d exited, status: %d", pid, WEXITSTATUS(status));
}

static void
process_signaled(int pid, int status)
{
	debug1("process pid: %d killed by signal %d (%s)", 
	     pid, WTERMSIG(status), strsignal(WTERMSIG(status)));
}

static void
process_stopped(int pid, int status)
{
	debug1("process pid: %d stopped by signal %d", pid, WSTOPSIG(status));
}

static void
process_continued(int pid, int status)
{
	debug1("process pid: %d continued", pid);
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
	debug1("process pid: %d waiting for status", pid);
	int v, status;
	for (v = 0; v == 0 && secs > 0; secs--) {
		if ((v = waitpid(pid, &status, WNOHANG)) == -1)
			error("wait() reason=%s", strerror(errno));
		else if (v == 0)
			sleep(1);
		else 
			return process_status(pid, status);
	}

	error("process pid: %d did not respond within the timeframe", pid);
	kill(pid, SIGKILL);
	debug1("process pid: %d killed by signal %d", pid, 9);
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

static inline void
subprocess_free(struct process *proc)
{
	if (proc->arg)
		free(proc->arg);
	free(proc);
}

int
sched_workque_add(const char *arg)
{
	if (workque.waiting > max_job_queue)
		return -1;

	struct process *proc = subprocess_alloc();
	proc->type = TASK_WORKQUE;
	proc->self.id = getid();
	proc->arg  = arg ? strdup(arg) : NULL;
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
	int rv;
	if (!(revents & EV_READ))
		return;

	char buffer[8192] = {0};
	rv = read(w->fd, buffer, sizeof(buffer) - 1);
	if (rv < 1)
		goto error;

	buffer[rv] = 0;
	struct ipc_msg *req = (struct ipc_msg *)buffer;
	if (rv < sizeof(*req))
		goto error;

	int len = req->size - sizeof(*req);
	char *arg = len > 0 ? strmema((u8*)req + sizeof(*req), len) : NULL;

	debug4("ipc msg recv %s:%s %d bytes", 
	       s_ipc_msg[req->type], s_ipc_dir[req->dir], rv);

	switch (req->type) {
	case IPC_WORKQUE_ADD: {
		int id = sched_workque_add(arg);
		struct ipc_msg res = { 
			.type = IPC_WORKQUE_ADD, .dir  = IPC_RESPONSE, 
			.size = sizeof(res), .sid  = id
		};

		debug4("ipc msg send %s:%s %d bytes", 
		       s_ipc_msg[res.type], s_ipc_dir[res.dir], res.size);
		if ((rv = write(w->fd, &res, res.size)) < res.size)
			error("result=%d %d:%s", rv, errno, strerror(errno));
		break;

	}
	case IPC_STATUS: {
		int id = (*(int *)arg);
		struct pstatus *pstatus = pstatus_lookup_id(id);
		int size = pstatus ? sizeof(*pstatus): 0;
		
		struct ipc_msg *res = (struct ipc_msg *)buffer;
		*res = (struct ipc_msg) { 
			.type = IPC_STATUS, .dir  = IPC_RESPONSE, 
			.size = sizeof(*res) + size, .sid  = pstatus ? id : 0
		};

		if (size)
			memcpy(((u8*)res) + sizeof(*res), pstatus, size);

		debug4("ipc msg send %s:%s %d bytes", 
		       s_ipc_msg[res->type], s_ipc_dir[res->dir], res->size);
		if ((rv = write(w->fd, res, res->size)) < res->size)
			goto error;
		break;
	}
	default:
		write(w->fd, " ", 1);
	break;
	}

	ev_break(loop, EVBREAK_ALL);
	return;
error:
	error("result=%d %d:%s", rv, errno, strerror(errno));
	ev_break(loop, EVBREAK_ALL);
}

int
sched_sethist(struct task *proc, int id, struct task_status *status)
{
	return 0;
}

int
sched_gethist(struct task *proc, int id, struct task_status *status, int bsize)
{
	struct process *p = __container_of(proc, struct process, self);
	struct bb bb = { .addr = alloca(PIPE_BUF), .len = PIPE_BUF};
	int rv, len = sizeof(id);

	struct ipc_msg *m = (struct ipc_msg *)bb.addr;
	m->type = IPC_STATUS; 
	m->dir  = IPC_REQUEST; 
	m->size = sizeof(*m) + len;
	memcpy(((byte *)m) + sizeof(*m), &id, len);

	debug4("ipc msg send %s:%s %d bytes", 
	     s_ipc_msg[m->type], s_ipc_dir[m->dir], m->size);

	if ((rv = write(p->ipc[1], m, m->size)) < m->size)
		goto error;
	if ((rv = read(p->ipc[1], m, PIPE_BUF)) < m->size)
		goto error;

	debug4("ipc msg recv %s:%s %d bytes",
	     s_ipc_msg[m->type], s_ipc_dir[m->dir], rv);

	if (m->type != IPC_STATUS || m->dir != IPC_RESPONSE)
		return -1;
	if (m->size < (sizeof(*m) + sizeof(struct pstatus)))
		return -1;
	struct pstatus *pstatus = (struct pstatus *)((u8*)m + sizeof(*m));
	if (!pstatus)
		return -1;

	pstatus_info(pstatus);
	memcpy(&pstatus->self, status, sizeof(*status));
		
	return 0;

error:
	error("%d:%s", errno, strerror(errno));
	return -1;	
}


int
sched_workque(struct task *proc, const char *arg)
{
	struct process *p = __container_of(proc, struct process, self);
	struct bb bb = { .addr = alloca(PIPE_BUF), .len = PIPE_BUF};
	int rv, len = strlen(arg);

	struct ipc_msg *m = (struct ipc_msg *)bb.addr;
	m->type = IPC_WORKQUE_ADD; 
	m->dir  = IPC_REQUEST; 
	m->size = sizeof(*m) + len;
	memcpy(((byte *)m) + sizeof(*m), arg, len);

	debug4("ipc msg send %s:%s %d bytes", 
	     s_ipc_msg[m->type], s_ipc_dir[m->dir], m->size);

	if ((rv = write(p->ipc[1], m, m->size)) < m->size)
		goto error;
	if ((rv = read(p->ipc[1], m, sizeof(*m))) < sizeof(*m))
		goto error;

	debug4("ipc msg recv %s:%s %d bytes",
	     s_ipc_msg[m->type], s_ipc_dir[m->dir], rv);
	return m->sid;

error:
	error("%d:%s", errno, strerror(errno));
	return -1;	
}

static void
pstatus_touch(struct pstatus *pstatus, timestamp_t now)
{
	pstatus->modified = now;
	pstatus->expires = pstatus->modified + 360;
}

static void
pstatus_init(struct pstatus *pstatus, time_t now)
{
	pstatus->created = pstatus->modified = now;
	pstatus->self.state = TASK_RUNNING;
	pstatus_touch(pstatus, now);
	pstatus->size = sizeof(*pstatus);
}

static struct pstatus *
pstatus_alloc(pid_t pid, pid_t id, time_t now)
{
	struct pstatus *pstatus = (struct pstatus *)page_alloc_safe(pagemap);
	if (!pstatus)
		return NULL;

	pstatus_init(pstatus, now);

	pstatus->pid = pid;
	pstatus->id = id;
	pstatus->hash_id  = hash_data(hstatus_id, id);
	pstatus->hash_pid = hash_data(hstatus_pid, pid);
	pstatus->size = sizeof(*pstatus);

	hnode_init(&pstatus->n.id);
	hnode_init(&pstatus->n.pid);
	hash_add(hstatus_id, &pstatus->n.id, pstatus->hash_id);
	hash_add(hstatus_pid, &pstatus->n.pid, pstatus->hash_pid);
	return pstatus;
}

static void
pstatus_free(struct pstatus *pstatus)
{
	debug2("process status cache id: %u (pid: %u) expired.", 
	       (unsigned int)pstatus->id, (unsigned int)pstatus->pid);
	
	hash_del(&pstatus->n.id);
	hash_del(&pstatus->n.pid);
	page_free(pagemap, (struct page *)pstatus);
}

static struct pstatus *
pstatus_create(pid_t pid, pid_t id)
{
	timestamp_t now = get_timestamp();

	hash_for_each_delsafe(hstatus_pid, it, hash_data(hstatus_pid, pid)) {
		struct pstatus *p = __container_of(it, struct pstatus, n.pid);
		if ((now > p->expires) || pid == p->pid)
			pstatus_free(p);
	}

	return pstatus_alloc(pid, id, now);
}

static struct pstatus *
pstatus_lookup_pid(pid_t pid)
{
	time_t now = secs_now();

	hash_for_each_delsafe(hstatus_pid, it, hash_data(hstatus_pid, pid)) {
		struct pstatus *p = __container_of(it, struct pstatus, n.pid);
		if ((now > p->expires))
			pstatus_free(p);
		else if (p->pid == pid)
			return p;
	}
	return NULL;
}

static struct pstatus *
pstatus_lookup_id(pid_t id)
{
	time_t now = secs_now();

	hash_for_each_delsafe(hstatus_id, it, hash_data(hstatus_id, id)) {
		struct pstatus *p = __container_of(it, struct pstatus, n.id);
		if ((now > p->expires))
			pstatus_free(p);
		else if (p->id == id)
			return p;
	}

	return NULL;
}

static void
pstatus_info(struct pstatus *p)
{
	char *v = p->self.state == TASK_FINISHED ? 
		printfa(" status: %d", p->self.exitcode): "";

	debug2("status cache id: %d (pid: %d, state: %s%s))",
	       (int)p->id, (int)p->pid, task_sget_state(p->self.state), v);

	debug4("status cache id: %d (modified: %lld expires: %lld {%d})", 
	       (int)p->id, 
	       (long long int)p->modified, 
	       (long long int)p->expires,
	       (int)(p->expires - p->modified));
}

static int
pstatus_update_state(pid_t pid, int state, int status, int exitcode)
{
	struct pstatus *pstatus = pstatus_lookup_pid(pid);
	if (!pstatus)
		return -1;

	time_t now = secs_now();
	pstatus->self.state = state;
	pstatus->self.status = status;
	pstatus->self.exitcode = exitcode;
	pstatus_info(pstatus);
	pstatus_touch(pstatus, now);
	return 0;
}

static inline void
subprocess_attach(struct process *proc)
{
	ev_child_init(&proc->ev.child, chld_handler, proc->self.pid, 1);
	ev_child_start(EV_DEFAULT_ &proc->ev.child);

	ev_io_init(&proc->ev.ipc, ipc_handler,  proc->ipc[0], EV_READ);
	ev_io_start(EV_DEFAULT_ &proc->ev.ipc);
	debug4("subprocess pid: %d attach: %p", proc->self.pid, &proc->ev.ipc);

	struct pstatus *pstatus = pstatus_create(proc->self.pid, proc->self.id);
	if (!pstatus)
		goto error;

	time_t now = secs_now();
	pstatus_init(pstatus, now);
	pstatus_info(pstatus);
	return;
error:
	error("Can't create history for subprocess pid: %d", proc->self.pid);
}

static inline void
subprocess_detach(struct process *proc)
{
	proc->self.state = TASK_INACTIVE;

	ev_child_stop(EV_DEFAULT_ &proc->ev.child);
	ev_io_stop(EV_DEFAULT_ &proc->ev.ipc);
	close(proc->ipc[0]);
	close(proc->ipc[1]);
	debug4("subprocess pid=%d detach: %p", proc->self.pid, &proc->ev.ipc);

	pstatus_update_state(proc->self.pid,
	                     WIFEXITED(proc->self.status) ? 
			     TASK_FINISHED: TASK_INACTIVE,
	                     proc->self.status, proc->self.exitcode);
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
		if (WIFEXITED(w->rstatus))
			c->self.exitcode = WEXITSTATUS(w->rstatus);
		if (WIFEXITED(w->rstatus) || WIFSIGNALED(w->rstatus)) {
			workers.running--;
			c->self.status = w->rstatus;
			subprocess_detach(c);
		}
	}

	list_for_each_delsafe(workque.run, node) {
		c = __container_of(node, struct process, queued);
		if (w->rpid != c->self.pid)
			continue;
		if (WIFEXITED(w->rstatus))
			c->self.exitcode = WEXITSTATUS(w->rstatus);
		if (WIFEXITED(w->rstatus) || WIFSIGNALED(w->rstatus)) {
			workque.running--;
			c->self.status = w->rstatus;
			subprocess_detach(c);
			list_del(&c->queued);
			subprocess_free(c);
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
do_ctor_proc(struct process *proc)
{
	sig_action(SIGHUP, hup_handler);
	sig_disable(SIGTERM);
	sig_disable(SIGINT);
	sig_disable(SIGUSR1);
	sig_disable(SIGUSR2);
	sig_ignore(SIGINT);
	sig_ignore(SIGTERM);

	proc->self.pid = getpid();

	if (task_is_workque(&proc->self))
		callback->workque.ctor(&proc->self);
	else
		callback->process.ctor(&proc->self);
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

	if (callback->process.dtor)
		callback->process.dtor(&proc->self);

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
		int exitcode = 0;
		while(!request_restart && !request_shutdown) {
			if (callback->process.entry)
				exitcode = callback->process.entry(task);
		}
		do_dtor(proc);
		exit(exitcode);
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

	if (!t2->id)
		t2->id = getid();

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
	exit(proc->self.exitcode);
}

static inline void
do_workque(struct process *proc)
{
	struct task *task = &proc->self;
	task->pid = getpid();
	proc->type = TASK_WORKQUE;

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

	int exitcode = 0;
	if (callback->workque.entry)
		exitcode = callback->workque.entry(&proc->self);

	do_dtor(proc);
	close(proc->ipc[1]);
	exit(exitcode);
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

int
sched_timeout_interuptible(int timeout)
{
	return 0;
}

int
sched_timeout_uninteruptible(int timeout)
{
	return 0;
}

int
sched_timeout_killable(int timeout)
{
	return 0;
}

int
sched_timeout_throttled(int timeout)
{
	return 0;
}

void
_sched_start(const struct mpm_module *mpm_module)
{
	hash_init(hstatus_id);
	hash_init(hstatus_pid);

	list_init(&workers.list);
	list_init(&workque.run);
	list_init(&workque.que);

	params   = mpm_module->params;
	callback = mpm_module->callbacks;

	if ((params->max_processes - params->max_job_parallel) < 1 )
		die("increase max_processes parameter");

	workers.total = params->max_processes - params->max_job_parallel;
	do_ctor(&root);

	debug2("scheduler noop registered");
	debug2("scheduler deadline registered");
	debug2("scheduler config registered");
	debug2("scheduler queue registered");
	debug2("scheduler mq-deadline registered");
	debug2("scheduler roundrobin registered");
	debug2("scheduler cache-status registered");

	int pages = 512;
	int shift = 12;

	pagemap = mmap_open(NULL, MAP_SHARED | MAP_ANON, shift, pages);
	if (!pagemap)
		die("map():%d:%s", errno, strerror(errno));

	unsigned long long pageb = (unsigned long long)pages2b(shift, pages);
	debug2("status cache hash table entries: %d (shift: %d, %llu bytes)", 
	       (int)hash_entries(hstatus_id), (int)hash_bits(hstatus_id),
	       (unsigned long long)sizeof(hstatus_id) * array_size(hstatus_id));
	debug2("status cache memory pages: %d (shift: %d, %llu bytes)",
	       pages, shift, pageb);

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
	
	if (pagemap)
		mmap_close(pagemap);

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
