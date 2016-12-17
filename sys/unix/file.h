/*
 * Generic file interface over several platforms
 *
 * The MIT License (MIT)         Copyright (c) 2015 Daniel Kubec <niel@rtfm.cz> 
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
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef __CLIB_FILE_H__
#define __CLIB_FILE_H__

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

/* 
 * POSIX.1-2008
 *
 * Atomic/non-atomic: A write is atomic if the whole amount written in one 
 * operation is not interleaved with data from any other process. 
 * This is useful when there are multiple writers sending data to a single 
 * reader. Applications need to know how large a write request can be expected 
 * to be performed atomically. This maximum is called {PIPE_BUF}. This volume 
 * of POSIX.1-2008 does not say whether write requests for more than {PIPE_BUF}
 * bytes are atomic, but requires that writes of {PIPE_BUF} or fewer bytes 
 * shall be atomic.
 *
 * The value if PIPE_BUF is defined by each implementation, but the minimum is 
 * 512 bytes (see limits.h).
 */

#define FILE_WRITE_ATOMIC  0x01

/* A private structure containing the file object */
struct file;

int
file_write(struct file *file, const void *msg, size_t size, int flags);

extern struct file *file_stdout;
extern struct file *file_stderr;

#endif/*__CLIB_FILE_LIB_H__*/
