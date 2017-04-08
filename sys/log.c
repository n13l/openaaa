#include <sys/compiler.h>
#include <sys/log.h>
#include <list.h>
#include <unistd.h>
#include <string.h>

void *log_userdata = NULL;
int log_verbose = 4;
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

	ctx->user = log_userdata;

	if (len < 1)
		return;

	if (log_write_cb) {
		log_write_cb(ctx, msg, len);
	} else {
		byte amsg[512];
		snprintf(amsg, sizeof(amsg) - 1, "%s:%s %s\n", 
		         ctx->module, ctx->fn, msg);
		write(0, amsg, strlen(amsg));
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
