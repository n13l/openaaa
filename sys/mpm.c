#include <sys/compiler.h>
#include <sys/log.h>
#include <mem/stack.h>
#include <signal.h>

#include <net/proto.h>
#include <list.h>
#include <copt/lib.h>
	
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

static sig_atomic_t request_shutdown = 0;
static sig_atomic_t request_restart  = 0;
static sig_atomic_t request_info     = 0;

/* processes or per_cpu should not be set together */
int sched_processes                   = 1; 
int sched_per_cpu                     = 1;
int sched_max_workers                 = 4;
int sched_max_jobs                    = 1;
int sched_timeout_job                 = 0;
int sched_timeout_gracefull_shutdown  = 15; 


