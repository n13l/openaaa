
#include <sys/compiler.h>
#include <sys/cpu.h>
#include <sys/log.h>
#include <sys/types.h>
#include <list.h>

#define EV_API_STATIC 1
#define EV_STANDALONE 1
#define EV_MINIMAL 1
#define EV_EMBED_ENABLE 1
#define EV_USE_POLL 0
#define EV_MULTIPLICITY 1
#define EV_PERIODIC_ENABLE 0
#define EV_STAT_ENABLE 0
#define EV_FORK_ENABLE 1
#define EV_GENWRAP 0
#define EV_AVOID_STDIO 0
#define EV_NO_THREADS 0
#undef EV_API_DECL

#include <sys/ev/ev.c>

enum task_type_e {
	TASK_TYPE_NONE      = 0,
	TASK_TYPE_DISP,          /* dispatcher */
	TASK_TYPE_PROC,          /* process    */
	TASK_TYPE_TH,            /* thread     */
};

int
task_type(void)
{
	return getpid() == gettid();
}

static void                                                                     
task_signal_cb(struct ev_loop *loop, ev_signal *w, int revents)                    
{                                                                               
	write(1, "\n", 1);
	debug("%s processed", strsignal(w->signum));
	if (w->signum == SIGTERM || w->signum == SIGINT)
		ev_break (loop, EVBREAK_ALL);
}

struct task {
	struct ev_loop *ev_loop;
	struct ev_signal signals[32];
	struct ev_signal sigint_watcher;
	struct ev_signal sigterm_watcher;
	struct ev_signal sighup_watcher;
	unsigned int index;
	unsigned int id;
	struct list list;
	struct node node;
} task;

void
task_init(struct task *task)
{
	node_init(&task->node);
	list_init(&task->list);

	task->ev_loop = ev_default_loop(0);
	/* setup signal handlers */

	ev_signal_init(&task->sigint_watcher,  task_signal_cb, SIGINT);
	ev_signal_init(&task->sigterm_watcher, task_signal_cb, SIGTERM);
	ev_signal_init(&task->sighup_watcher,  task_signal_cb, SIGHUP);
	ev_signal_start(task->ev_loop, &task->sigint_watcher);
	ev_signal_start(task->ev_loop, &task->sigterm_watcher);
	ev_signal_start(task->ev_loop, &task->sighup_watcher);

}

void
task_fini(struct task *task)
{
}

int
task_wait(struct task *task)
{
	debug("dispatcher=%s", task_type() ? "yes" : "no");
	ev_loop(task->ev_loop, 0);
	return 0;
}

void
sched_init(void)
{
	task_init(&task);
	debug("started");
}

void
sched_wait(void)
{
	task_wait(&task);
}

void
sched_fini(void)
{
	debug("stopped");
	task_fini(&task);
}


int
aaa_server(int argc, char *argv[])
{
	info("starting server");
	return 0;
}


