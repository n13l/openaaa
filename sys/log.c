#include <sys/compiler.h>
#include <sys/log.h>
#include <mem/alloc.h>
#include <mem/stack.h>
#include <unistd.h>
#include <string.h>
#include <unix/timespec.h>

#include <syslog.h>
#include <sys/log.h>

static const char *log_lnames[] = {
	[LOG_ERROR]  = "error",
	[LOG_INFO]   = "info",
	[LOG_WARN]   = "warn",
	[LOG_DEBUG]  = "debug",
	[LOG_DEBUG1] = "debug1",
	[LOG_DEBUG2] = "debug2",
	[LOG_DEBUG3] = "debug3",
	[LOG_DEBUG4] = "debug4",
};

int log_caps = 0;
int log_type = 0;

void *log_userdata = NULL;
int log_verbose = 0;
char progname[256] = {0};

void (*log_write_cb)(struct log_ctx *ctx, const char *msg, int len) = NULL;

void
log_open(const char *file, int facility)
{
	if (!strcmp(file, "syslog")) 
		log_type = LOG_TYPE_SYSLOG;

	switch (log_type) {
	case LOG_TYPE_SYSLOG: 
		openlog(progname, LOG_CONS | LOG_PID | LOG_NDELAY, facility);
		break;
	}
}

void
log_name(const char *name)
{
	strcpy(progname, name);
}

void
log_close(void)
{
	switch (log_type) {
	case LOG_TYPE_SYSLOG:
		closelog();
		break;
	}
}

void
log_custom_set(log_write_fn fn, void *ctx)
{
	log_write_cb = fn;
	log_userdata = ctx;
}

void
log_setcaps(int caps)
{
	log_caps = caps;
}

int
log_getcaps(void)
{
	return log_caps;
}

void
log_vprintf(struct log_ctx *ctx, const char *fmt, va_list args)
{
	char line[2048], *pline;
	byte msg[1024];
	va_list args2;
	va_copy(args2, args);
	int len = vsnprintf(msg, sizeof(msg) - 2, fmt, args2);
	va_end(args2);

	int size = sizeof(line) - 2;
	pline = line;

	static struct timeval start = {0};
	static int started = 1;
	struct timeval now;

	if (started)
		gettimeofday(&start, NULL);

	gettimeofday(&now, NULL);
	if (started)
		started = 0;

	if (log_caps & LOG_CAP_LEVEL)
		pline += snprintf(pline, size, "%6s: ", log_lnames[ctx->level]);

	if (log_caps & LOG_CAP_TIMESTAMP)
		pline += snprintf(pline, size, "%08u.%06u ", 
		                 (unsigned int)(now.tv_sec - start.tv_sec), 
		                 (unsigned int)now.tv_usec);

	if (log_caps & LOG_CAP_PID)
		pline += snprintf(pline, size, "%d ", (int)getpid());
	if (log_caps & LOG_CAP_MODULE)
		pline += snprintf(pline, size, "%s ", ctx->module);
	if (log_caps & LOG_CAP_FN)
		pline += snprintf(pline, size, "%s ", ctx->fn);

	*pline = 0;

	ctx->user = log_userdata;
	if (len < 1)
		return;

	if (log_write_cb) {
		log_write_cb(ctx, msg, len);
	}

	byte amsg[1024];
	snprintf(amsg, sizeof(amsg) - 1, "%s%s\n",
	         line, msg);
#ifdef WIN32
	fprintf(stdout, "%s", amsg);
	fflush(stdout);
#else
	switch (log_type) {
	case LOG_TYPE_SYSLOG:
		syslog(ctx->level > 7 ? 7 : ctx->level, "%s", amsg);
		break;
	default:
		write(0, amsg, strlen(amsg));
		break;
	}
#endif
}

void
log_printf(struct log_ctx *ctx, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	log_vprintf(ctx, fmt, args);
	va_end(args);
}
