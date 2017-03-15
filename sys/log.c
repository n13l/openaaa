#include <sys/compiler.h>
#include <sys/log.h>
#include <list.h>

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
log_custom_set(log_write_fn fn)
{
	log_write_cb = fn;
}

void
log_vprintf(struct log_ctx *ctx, const char *fmt, va_list args)
{
	byte msg[512];
	va_list args2;
	va_copy(args2, args);
	int len = vsnprintf(msg, sizeof(msg) - 2, fmt, args2);
	va_end(args2);

	if (len < 1)
		return;

	if (log_write_cb) {
		log_write_cb(ctx, msg, len);
	} else {
		msg[len] = '\n';
		msg[len + 1] = 0;
		write(0, msg, len + 1);
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
