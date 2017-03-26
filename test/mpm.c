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

#include <sys/compiler.h>
#include <sys/cpu.h>
#include <sys/log.h>
#include <sys/types.h>
#include <list.h>

#define EV_STANDALONE 1
#define EV_MINIMAL 1
#define EV_EMBED_ENABLE 1
#define EV_USE_POLL 0
#define EV_MULTIPLICITY 1
#define EV_PERIODIC_ENABLE 0
#define EV_STAT_ENABLE 0
#define EV_FORK_ENABLE 1
#include <sys/ev/ev.c>

int
task_dispatcher(void)
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
};

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
	debug("dispatcher=%s", task_dispatcher() ? "yes" : "no");
	ev_loop(task->ev_loop, 0);
	return 0;
}

int 
main(int argc, char *argv[]) 
{
	debug("mpm started");
	debug("sizeof ev_signal=%d", (int) sizeof(struct ev_signal));

	struct task self;
	task_init(&self);
	task_wait(&self);

	return 0;
}
