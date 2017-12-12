#ifndef __SYS_MPM_H__
#define __SYS_MPM_H__

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

#define CPU_SHARED       0x0001 /* shared mapped regions */
#define CPU_DEDICATED    0x0002 /* processes does not share anything */

#define TASK_INACTIVE    0x0001 /* task is not active but resource are there */
#define TASK_STOPPED     0x0002 /* task has been stopped */
#define TASK_RUNNING     0x0004 /* task is running */
#define TASK_EXITING     0x0008 /* task is in exiting state */
#define TASK_WORKQUE     0x0010 /* task is in work queue */

int task_is_inactive(void);
int task_is_running(void);
int task_in_workque(void);

struct task {
	timestamp_t created;
	timestamp_t expires;
	timestamp_t modified;
	int ppid, pid, index;
	volatile int state;
	int version;
	int status;
	int ipc[2];
};

enum task_type {
	TASK_TYPE_DISP    = 1,
	TASK_TYPE_PROC    = 2,
	TASK_TYPE_JOB     = 3
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

void _sched_init(void);
void _sched_wait(void);
void _sched_fini(void);

int sched_sendmsg(int id, void *addr, size_t size);
int sched_recvmsg(int id, void *addr, size_t size);
int sched_workque(int argc, char *argv[]);

int (*ctor_task)(struct task *);
int (*main_task)(struct task *);
int (*dtor_task)(struct task *);

#endif
