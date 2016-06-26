/*
 * The MIT License (MIT)                             Generic tracing facilities        
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
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 **/

#ifndef __GENERIC_TRACE_H__
#define __GENERIC_TRACE_H__

#include <sys/compiler.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <errno.h>

#define __syscall_error(fn, args)                                             \
do { printf("%s: %s %s %s\n", __func__, fn, args, strerror(errno)); } while(0)

static inline bool
syscall_voidp(void *arg) { return arg ? false: true;}

static inline bool 
syscall_filep(FILE *arg) { return arg ? false: true;}

static inline bool 
syscall_int  (int arg)   { return arg >= 0 ? false: true;}

static inline bool 
syscall_lint (long int arg){ return arg >= 0 ? false: true;}

#define __syscall_die(fn, args...) \
({ \
	__typeof__(fn args) __v = fn args; \
 	if (unlikely(_generic((__v), int     : syscall_int, \
	                             long int: syscall_lint, \
	                             void *  : syscall_voidp, \
	                             FILE *  : syscall_filep)(__v))) \
		{ __syscall_error(#fn, #args); exit(errno);} \
	__v; \
})

#endif
