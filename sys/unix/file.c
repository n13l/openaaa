/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2013 Daniel Kubec <niel@rtfm.cz>
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
 */

#include <sys/compiler.h>
#include <sys/cpu.h>
#include <sys/log.h>

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>

#include <unix/file.h>

#ifndef PIPE_BUF
#define PIPE_BUF 512
#endif

int
file_writev(struct file *file, const char *fmt, va_list args);

int
file_writef(struct file *file, const char *fmt, ...);

int
file_write(struct file *file, const void *msg, size_t size, int flags);

/* File object operations */
struct file_operations {
	int  (*open)(struct file *file, const char *name, int flags);
	int  (*read)(struct file *file, const void *msg, size_t size);
	int  (*write)(struct file *file, const void *msg, size_t size, int f);
	int  (*writef)(struct file *file, const char *fmt, ...);
	int  (*writev)(struct file *file, const char *fmt, va_list args);
	int  (*seek)(struct file *file, off_t pos, int whence);
	void (*close)(struct file *file);
};

struct file_operations posix_ops = {
	.write     = file_write,
	.writef    = file_writef,
	.writev    = file_writev
};

struct file {
	int fd;
	struct file_operations op;
};

static int
atomic_writev(int fd, const char *fmt, va_list args)
{
	va_list args2;
	char msg[PIPE_BUF];

	va_copy(args2, args);
	int size = vsnprintf(msg, sizeof msg - 1, fmt, args2);
	va_end(args2);

	size_t rest = size > PIPE_BUF ? size - PIPE_BUF : 0;
	if (likely(rest == 0))
		return write(fd, msg, size);
	else
		return -ENOSYS;
}

static int
atomic_writef(int fd, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	int rv = atomic_writev(fd , fmt, args);
	va_end(args);
	return rv;
}

static inline int
atomic_write(int fd, const void *msg, size_t size)
{
	size_t rest = size > PIPE_BUF ? size - PIPE_BUF : 0;
	if (likely(rest == 0))
		return write(fd, msg, size > PIPE_BUF ? PIPE_BUF: size);
	else
		return -ENOSYS;
}

int
file_writev(struct file *file, const char *fmt, va_list args)
{
	return atomic_writev(file->fd, fmt, args);
}

int
file_writef(struct file *file, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	int rv = atomic_writef(file->fd, fmt, args);
	va_end(args);
	return rv;
}

int
file_write(struct file *file, const void *msg, size_t size, int flags)
{
	if (flags & FILE_WRITE_ATOMIC)
		return atomic_write(file->fd, msg, size);

	return atomic_write(file->fd, msg, size);	
}

struct file *file_stdout = NULL;
struct file *file_stderr = NULL;
