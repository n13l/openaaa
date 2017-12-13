/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2015, 2016, 2017                   Daniel Kubec <niel@rtfm.cz> 
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
 *
 * + high availability, race-free and lock-free multi processing modules
 *
 * + hybrid module which combines the best from processes and threads
 * + gracefull shutdown, cleanup and automatic worker recovery
 * + distributed workqueue management for workers and other subprocesses
 * + simple ipc messaging based on anonymous pipes 
 * + used for the popular unix design based on copy-on-write and fds derivation
 *
 */

#ifndef __SYS_MULTI_PROCESSING_MODULES_H__
#define __SYS_MULTI_PROCESSING_MODULES_H__

#include <sys/compiler.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <errno.h>
#include <time.h>
#include <buffer.h>

#define MPM_PREFORK      0x0001 /* copy-on-write */
#define MPM_THREADED     0x0002 /* multi threaded / sharing everything */
#define MPM_HYBRID       0x0004 /* prefork workers with threads */

#define CPU_SHARED       0x0001 /* processes sharing memory accross CPUs     */
#define CPU_DEDICATED    0x0002 /* processes does not share anything         */
#define CPU_AFFINITY     0x0004 /* processes are binded to specified CPUs    */

#define TASK_INACTIVE    0x0001 /* task is not active but resource are there */
#define TASK_STOPPED     0x0002 /* task has been stopped */
#define TASK_RUNNING     0x0004 /* task is running */
#define TASK_EXITING     0x0008 /* task is in exiting state */
#define TASK_WORKQUE     0x0010 /* task is in work queue */

/* subprocess is interupted with SIGHUP when parent dies based on PDEATHSIG  */
#define TASK_PDEATHSIGHUP 0x0001 
/* subprocess is interupted with SIGHUP when parent dies based on custom irq */
#define TASK_PDEATHIRQHUP 0x0002

struct task {
	timestamp_t created;
	timestamp_t expires;
	int ppid, pid, index;
	volatile int state;
	int version;
	int status;
	int ipc[2];
};

struct mpm_callbacks {
	int (*init)(void);
	int (*fini)(void);
	int (*ctor)(struct task *);
	int (*dtor)(struct task *);
	int (*entry)(struct task *, int argc, char *argv[]);
};

/* scheduling parameters */
struct sched_params {
	int max_processes;
	int max_threads;
	int per_cpu_proc;
	int per_cpu_thread;
	int max_job_parallel;
	int max_job_queue;
	int timeout_interuptible;
	int timeout_uninteruptible;
	int timeout_killable;
	int timeout_throttled;
};

void sched_timeout_interuptible(int timeout);
void sched_timeout_uninteruptible(int timeout);
void sched_timeout_killable(int timeout);
void sched_timeout_throttled(int timeout);
void sched_info_show(void);

int  sched_getcaps(void);
int  sched_setcaps(int caps);

void _sched_init(void);
void _sched_wait(void);
void _sched_fini(void);

int sched_sendmsg(int id, void *addr, size_t size);
int sched_recvmsg(int id, void *addr, size_t size);
int sched_workque(struct task *);

int (*ctor_task)(struct task *);
int (*main_task)(struct task *);
int (*dtor_task)(struct task *);

int task_is_inactive(struct task *);
int task_is_running(struct task *);
int task_is_workque(struct task *);

#endif
