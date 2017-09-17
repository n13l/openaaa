#ifndef __SYS_MPM_H__
#define __SYS_MPM_H__

#include <sys/compiler.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <errno.h>
#include <time.h>

/* forward declaration */
struct task;

enum task_type {
	TASK_TYPE_NONE    = 0,
	TASK_TYPE_DISP    = 1,   
	TASK_TYPE_PROC    = 2,   
	TASK_TYPE_WORK    = 3,   
	TASK_TYPE_LSNR    = 4,   
	TASK_TYPE_JOB     = 5
};

enum task_state {
	TASK_STATE_NONE   = 0,
	TASK_STATE_WORK   = 1,
	TASK_STATE_STOP   = 2,
	TASK_STATE_CONT   = 3,
	TASK_STATE_INIT   = 4,
	TASK_STATE_FINI   = 5,
};

struct sched_class {
	unsigned int per_cpu_proc;
	unsigned int per_cpu_thread;
	unsigned int workers;
};

#endif
