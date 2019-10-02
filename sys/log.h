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
 *
 * Logging code use stack, asynch-safe calls and atomic write() operation.
 *
 * POSIX.1 says that write(2)s of less than PIPE_BUF bytes must be atomic.
 * The precise semantics depend on whether the file descriptor is nonblocking.
 * 
 * Following log line if LOG_CAP_TIME is defined:
 *
 * +- month           +- process id
 * |  +- day          |     +- thread id      +- message
 * |  |               |     |                 |
 * 04-29 22:43:20.244 1000 1000 main          messag1e
 */

#ifndef __LOCKFREE_LOGGING_CAPABILITY_H__
#define __LOCKFREE_LOGGING_CAPABILITY_H__

#include <sys/compiler.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/log/atomic.h>

__BEGIN_DECLS

enum log_opt_e {
	LOG_OPT_SILENT    = 1,
	LOG_OPT_VERBOSITY = 2,
};

enum log_cap {
	LOG_CAP_LEVEL     = 1, 
	LOG_CAP_TIME      = 2, 
	LOG_CAP_TIMESTAMP = 4,
	LOG_CAP_PID       = 8,
	LOG_CAP_TID       = 16,
	LOG_CAP_USER      = 32,
	LOG_CAP_MODULE    = 64,
	LOG_CAP_FN        = 128,
};

enum log_msg {
	LOG_MSG_ERROR     = 1,
	LOG_MSG_WARN      = 2,
	LOG_MSG_INFO      = 3,
	LOG_MSG_DEBUG1    = 4,
	LOG_MSG_DEBUG2    = 5,
	LOG_MSG_DEBUG3    = 6,
	LOG_MSG_DEBUG4    = 7
};

/*
 * info()
 *
 * Prints a formatted info message 
 * @fmt    Format string for the message.
 * @args   Format arguments.
 */

#define info(fmt, ...) \
  INTERNAL_ASAFE_ATOMIC_PRINTF(LOG_INFO, 0, fmt, ## __VA_ARGS__)

/*
 * error()
 *
 * Prints a formatted error message 
 * @fmt    Format string for the message.
 * @args   Format arguments.
 */

#define error(fmt, ...) \
  INTERNAL_ASAFE_ATOMIC_PRINTF(LOG_ERROR, 0, fmt, ## __VA_ARGS__)

/*
 * warning()
 *
 * Prints a formatted error message 
 * @fmt    Format string for the message.
 * @args   Format arguments.
 */

#define warning(fmt, ...) \
  INTERNAL_ASAFE_ATOMIC_PRINTF(LOG_WARN, 0, fmt, ## __VA_ARGS__)

/*
 * die()
 *
 * Prints a formatted error message and call exit()
 * @fmt    Format string for the message.
 * @args   Format arguments.
 */

#define die(fmt, ...) \
({ \
  INTERNAL_ASAFE_ATOMIC_PRINTF(LOG_ERROR, 0, fmt, ## __VA_ARGS__); exit(1);\
})

/*
 * debug1()
 *
 * Prints a formatted level 1 messages
 * @fmt    Format string for the message.
 * @args   Format arguments.
 */


#define debug1(fmt, ...) \
  INTERNAL_ASAFE_ATOMIC_PRINTF(LOG_DEBUG1, 1, fmt, ## __VA_ARGS__)

/*
 * debug2()
 *
 * Prints a formatted level 2 messages
 * @fmt    Format string for the message.
 * @args   Format arguments.
 */

#define debug2(fmt, ...) \
  INTERNAL_ASAFE_ATOMIC_PRINTF(LOG_DEBUG2, 2, fmt, ## __VA_ARGS__)

/*
 * debug3()
 *
 * Prints a formatted level 3 messages
 * @fmt    Format string for the message.
 * @args   Format arguments.
 */

#define debug3(fmt, ...) \
  INTERNAL_ASAFE_ATOMIC_PRINTF(LOG_DEBUG3, 3, fmt, ## __VA_ARGS__)

/*
 * debug4()
 *
 * Prints a formatted level 4 messages
 * @fmt    Format string for the message.
 * @args   Format arguments.
 */

#define debug4(fmt, ...) \
  INTERNAL_ASAFE_ATOMIC_PRINTF(LOG_DEBUG4, 4, fmt, ## __VA_ARGS__)

/*
 * debug2_buf()
 *
 * Prints a formatted level 2 message
 *
 * @prefix Static prefix text
 * @indent Size of indent
 * @buf    Data
 * @size   Size of buffer
 */

#define debug2_buf(prefix, indent, buf, size) \
  INTERNAL_LOG_B16_ATOMIC(LOG_DEBUG2, 2, prefix, indent, buf, size)

void
log_name(const char *name);

void
log_open(const char *file);

void
log_close(void);

void
log_setcaps(int caps);

void
log_set_handler(void (*handler)(const char *, const char *));

int
log_getcaps(void);

extern int log_verbose;
extern int log_silent;

__END_DECLS

#endif
