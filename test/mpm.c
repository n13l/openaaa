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
#include <sys/mpm.h>

static int
ctor(struct task *task)
{
	setproctitle("mpm/%d", task->index);
	info("process pid=%d index=%d started", task->pid, task->index);
	return 0;
}

static int
dtor(struct task *task)
{
	info("process pid=%d index=%d stopped", task->pid, task->index);
	return 0;
}

static int
entry(struct task *task)
{
	sleep(20);
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
	setproctitle_init(argc, argv);
	setproctitle("mpmd");

	ctor_task = ctor;
	dtor_task = dtor;
	main_task = entry;

	log_setcaps(15);
	log_verbose = 1;	

	info("scheduler started.");
	_sched_init();
	_sched_wait();
	_sched_fini();
	info("scheduler stopped.");

	return 0;
}
