/*
 * Lock-free and asynch-safe logging capability
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2012-2018                          Daniel Kubec <n13l@rtfm.cz>
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
 * Logging code use stack, asynch-safe calls and atomic write() operation.
 *
 * POSIX.1 says that write(2)s of less than PIPE_BUF bytes must be atomic.
 * The precise semantics depend on whether the file descriptor is nonblocking.
 * 
 * https://tools.ietf.org/html/rfc5424
 * Asynch-safe syslog()
 *
 * Logging code support for outputting syslog, just uses the regular C library 
 * syslog() function. The problem is that this function is not async signal safe, 
 * mostly because of its use of the printf family of functions internally. 
 * Annoyingly libvirt does not even need printf support here, because it has 
 * already expanded the log message string.
 *
 * Following log line if LOG_CAP_TIME is defined:
 *
 *	 +- month           +- process id
 *	 |  +- day          |      +- thread id      +- message
 *	 |  |               |      |                 |
 *	 04-29 22:43:20.244 1000  1000               example:  Hi 
 */

#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#include <sys/compiler.h>
#include <sys/log.h>
#include <list.h>
#include <mem/alloc.h>
#include <mem/stack.h>
#include <sys/time.h>
#include <sys/log.h>
#include <sys/tid.h>
#include <syslog.h>

/* POSIX.1 requires PIPE_BUF to be at least 512 bytes. */
#ifndef PIPE_BUF
#define PIPE_BUF 512
#endif

#ifndef LOG_USER
#define LOG_USER        (1<<3)  /* random user-level messages */
#endif
#ifndef LOG_DAEMON
#define LOG_DAEMON      (3<<3)  /* system daemons */
#endif
#ifndef LOG_AUTH
#define LOG_AUTH        (4<<3)  /* security/authorization messages */
#endif
#ifndef LOG_AUTHPRIV
#define LOG_AUTHPRIV    (10<<3) /* security/authorization messages (private) */ 
#endif

static const char *type_names[] = {
	[LOG_ERROR]  = "error",
	[LOG_INFO]   = "info",
	[LOG_WARN]   = "warn",
	[LOG_DEBUG]  = "debug",
	[LOG_DEBUG1] = "debug1",
	[LOG_DEBUG2] = "debug2",
	[LOG_DEBUG3] = "debug3",
	[LOG_DEBUG4] = "debug4"
};

enum log_out {
	LOG_TYPE_SYSLOG   = 1,
	LOG_TYPE_STDOUT   = 2,
	LOG_TYPE_STDERR   = 3,
	LOG_TYPE_FILE     = 4,
};


static int log_caps = 0;
static int log_type = 0;

void *log_userdata = NULL;
int log_verbose = 0;
int log_silent = 0;
char progname[256] = {0};
int log_fd = -1;
static struct timeval start = {0};
static int started = 1;

void (*log_msg_handler)(const char *prefix, const char *msg) = NULL;

void
log_open(const char *file)
{
	log_type = 0;
	if (!strcmp(file, "stdout"))
		log_type = LOG_TYPE_STDOUT;
	else if (!strcmp(file, "stderr"))
		log_type = LOG_TYPE_STDERR;
	else if (!strcmp(file, "syslog"))
		log_type = LOG_TYPE_SYSLOG;

	switch (log_type) {
	case LOG_TYPE_STDOUT:
		log_fd = fileno(stdout);
		break;
	case LOG_TYPE_STDERR:
		log_fd = fileno(stderr);
		break;
	case LOG_TYPE_SYSLOG:
		openlog(progname, LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
		break;
	default:
		log_fd = open(file, O_CREAT | O_RDWR | O_TRUNC, 0644);
		break;
	}
}

void
log_set_handler(void (*handler)(const char *, const char *))
{
	log_msg_handler = handler;
}

void
log_name(const char *name)
{
	snprintf(progname, sizeof(progname) - 1, "%s", name);
}

void
log_close(void)
{
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

/* 
 * This functions returns the number of secs and usec elapsed since the program
 * was launched. 
 * */

static inline void
do_log_cap_timestamp(struct log_ctx *c)
{
	if (!(log_caps & LOG_CAP_TIMESTAMP))
		return;
	struct timeval now;
	gettimeofday(&now, NULL);
	if (started) {
		gettimeofday(&start, NULL);
		now = start;
		started = 0;
	}

	c->secs = now.tv_sec - start.tv_sec;
	c->usec = now.tv_usec;
}

static inline int
do_log_hdr_parse(struct log_ctx *c, char *p, int av)
{
	int sz = 0;
	do_log_cap_timestamp(c);
	if (log_caps & LOG_CAP_LEVEL)
		sz += snprintf(p + sz, av - sz, "%6s: ", type_names[c->type]);
	if (log_caps & LOG_CAP_TIMESTAMP)
		sz += snprintf(p + sz, av - sz, "%08u.%06u ",c->secs, c->usec);
	if (log_caps & LOG_CAP_PID)
		sz += snprintf(p + sz, av - sz, "%u ", getpid());
	if (log_caps & LOG_CAP_TID)
		sz += snprintf(p + sz, av - sz, "%u ", compat_gettid());
	if (log_caps & LOG_CAP_MODULE)
		sz += snprintf(p + sz, av - sz, "%s ", c->mod);
	if (log_caps & LOG_CAP_FN)
		sz += snprintf(p + sz, av - sz, "%s:%s:%d ", 
		               c->fn, c->file, c->line);
	return sz;
}

 /*
 * Logging code use stack, asynch-safe calls and atomic write() operation.
 *
 * POSIX.1 says that write(2)s of less than PIPE_BUF bytes must be atomic.
 * The precise semantics depend on whether the file descriptor is nonblocking.
 *
 * http://man7.org/linux/man-pages/man7/signal-safety.7.html
 *
 * According to the man page signal(7), the POSIX function clock_gettime() is 
 * listed as a safe function which can be called safely from a signal handler. 
 */

void
internal_asafe_vprintf(struct log_ctx *c, const char *fmt, va_list args)
{
	char msg[PIPE_BUF];
	int sz = do_log_hdr_parse(c, msg, PIPE_BUF - 4);
	char *text, *p = msg + sz;

	va_list args2;
	va_copy(args2, args);
	sz += vsnprintf(p, PIPE_BUF - sz - 2, fmt, args2);
	va_end(args2);

	text = p;
	p = msg + sz; *p++ = '\n'; *p++ = 0; sz += 1;

	if (log_msg_handler) {
		log_msg_handler("", text);
	} 
	if (log_fd != -1)
		sz = write(log_fd, msg, sz);
	else if (log_type == LOG_TYPE_SYSLOG) {
		syslog(c->type, msg);
	}
}

void
internal_asafe_printf(struct log_ctx *ctx, const char *fmt, ...)
{
	if (log_silent)
		return;

	va_list args;
	va_start(args, fmt);
	internal_asafe_vprintf(ctx, fmt, args);
	va_end(args);
}

static inline size_t
strlcpy(char *dst, const char *src, size_t siz)
{
	char *d = dst;
	const char *s = src;
	size_t n = siz;

	if (n != 0) {
		while (--n != 0)
			if ((*d++ = *s++) == '\0')
				break;
	}

	if (n == 0) {
		if (siz != 0)
			*d = '\0';
		while (*s++);
	}

	return(s - src - 1);
}

static inline size_t
strlcat(char *dst, const char *src, size_t siz)
{
	char *d = dst;
	const char *s = src;
	size_t dlen, n = siz;

	while (n-- != 0 && *d != '\0')
		d++;
	dlen = d - dst;
	n = siz - dlen;

	if (n == 0)
		return(dlen + strlen(s));
	while (*s != '\0') {
		if (n != 1) {
			*d++ = *s;
			n--;
		}
		s++;
	}
	*d = '\0';

	return(dlen + (s - src));
}


#define DUMP_WIDTH_LESS_INDENT(i) (16 -((i - (i > 6 ? 6:i) + 3) / 4))

static int
b16_indent(struct log_ctx *ctx, const char *prefix, int indent, 
           const char *s, int len)
{
    int ret = 0;
    char buf[288 + 1], tmp[20], str[128 + 1];
    int i, j, rows;
    unsigned char ch;
    int dump_width;

    if (indent < 0)
        indent = 0;
    if (indent) {
        if (indent > 128)
            indent = 128;
        memset(str, ' ', indent);
    }
    str[indent] = '\0';

    dump_width = DUMP_WIDTH_LESS_INDENT(indent);
    rows = (len / dump_width);
    if ((rows * dump_width) < len)
        rows++;
    for (i = 0; i < rows; i++) {
        strlcpy(buf, str, sizeof(buf));
        snprintf(tmp, sizeof(tmp), "%04x - ", i * dump_width);
        strlcat(buf, tmp, sizeof(buf));
        for (j = 0; j < dump_width; j++) {
            if (((i * dump_width) + j) >= len) {
                strlcat(buf, "   ", sizeof(buf));
            } else {
                ch = ((u8)*(s + i * dump_width + j)) & 0xff;
                snprintf(tmp, sizeof(tmp), "%02x%c", ch, j == 7 ? '-' : ' ');
                strlcat(buf, tmp, sizeof(buf));
            }
        }
        strlcat(buf, "  ", sizeof(buf));
        for (j = 0; j < dump_width; j++) {
            if (((i * dump_width) + j) >= len)
                break;
            ch = ((u8)*(s + i * dump_width + j)) & 0xff;
            snprintf(tmp, sizeof(tmp), "%c",
                         ((ch >= toascii(' ')) && (ch <= toascii('~')))
                         ? ch: '.');
            strlcat(buf, tmp, sizeof(buf));
        }

	char msg[PIPE_BUF];
	int sz = do_log_hdr_parse(ctx, msg, PIPE_BUF - 4);
	char *p = msg + sz;

	p = msg + sz; 
	sz += strlen(buf);
	memcpy(p, buf, strlen(buf));
	p += strlen(buf);
	
	*p++ = '\n'; *p++ = 0; sz += 1;
	
	sz = write(log_fd, msg, sz);
    }
    return ret;
}

void
internal_log_write_hex(struct log_ctx *ctx, const char *prefix, int indent, 
                       const u8 *buf, unsigned int size)
{
	if (log_silent)
		return;

	char msg[PIPE_BUF];
	int sz = do_log_hdr_parse(ctx, msg, PIPE_BUF - 4);
	char *p = msg + sz;

	p = msg + sz; *p++ = '\n'; *p++ = 0; sz += 1;
	b16_indent(ctx, prefix, indent, buf, size);
}


