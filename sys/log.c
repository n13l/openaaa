#include <sys/compiler.h>
#include <sys/log.h>
#include <mem/stack.h>

#include <unistd.h>
#include <string.h>
#include <unix/timespec.h>

void *log_userdata = NULL;
int log_verbose = 0;
char progname[256] = {0};

void (*log_write_cb)(struct log_ctx *ctx, const char *msg, int len) = NULL;

void
log_open(void)
{
	//openlog(progname, LOG_PID | LOG_NDELAY, LOG_LOCAL1);
}

void
log_close(void)
{
	///closelog();
}

void
log_custom_set(log_write_fn fn, void *ctx)
{
	log_write_cb = fn;
	log_userdata = ctx;
}

void
log_vprintf(struct log_ctx *ctx, const char *fmt, va_list args)
{
	byte msg[512];
	va_list args2;
	va_copy(args2, args);
	int len = vsnprintf(msg, sizeof(msg) - 2, fmt, args2);
	va_end(args2);

	static struct timeval start = {0};
	static int started = 1;
	struct timeval now;

	if (started)
		gettimeofday(&start, NULL);

	gettimeofday(&now, NULL);

	if (started)
		started = 0;
/*
	const char *module = printfa("%08u.%06u %s:%s", now.tv_sec - start.tv_sec, 
	                    now.tv_usec, ctx->module, ctx->fn);
*/
	const char *module = printfa("%08u.%06u ", (unsigned int)(now.tv_sec - start.tv_sec), 
	                    (unsigned int)now.tv_usec);

	ctx->user = log_userdata;
	if (len < 1)
		return;

	if (log_write_cb) {
		log_write_cb(ctx, msg, len);
	} else {
		_unused int pid = getpid();
		_unused int tid = gettid();
		byte amsg[512];
/*
		snprintf(amsg, sizeof(amsg) - 1, "%.8d:%.8d %s %s\n",
		         pid, tid, module, msg);
*/		snprintf(amsg, sizeof(amsg) - 1, "%s %s\n",
		         module, msg);

#ifdef WIN32
		fprintf(stdout, "%s", amsg);
		fflush(stdout);
#else
		write(0, amsg, strlen(amsg));
#endif
	}
}

void
log_printf(struct log_ctx *ctx, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	log_vprintf(ctx, fmt, args);
	va_end(args);
}
