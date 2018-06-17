/*
 * The MIT License (MIT)
 *                               Copyright (c) 2015 Daniel Kubec <niel@rtfm.cz> 
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
 */

#ifndef __SYS_TIMESPEC_H__
#define __SYS_TIMESPEC_H__

#include <time.h>

#define DEFINE_BENCHMARK(name) struct benchmark name = {0};

#define BENCHMARK_INIT(name) \
	timespec_now((struct timespec *)&name.init);
#define BENCHMARK_FINI(name) \
	timespec_now((struct timespec *)&name.fini); \
	name.elapsed = timespec_diff(&name.init, &name.fini); \

#define BENCHMARK_PRINT(name,call,fmt,...) \
({ \
	fprintf(stdout, fmt, ## __VA_ARGS__); fflush(stdout); \
 	BENCHMARK_INIT(name); call; BENCHMARK_FINI(name); \
 	double __elapsed = timespec_milliseconds(&name.elapsed); \
	fprintf(stdout, "\telapsed: %4.2f secs\n", ((double)__elapsed) / 1000.);\
})

struct benchmark {
	struct timespec init;
	struct timespec fini;
	struct timespec elapsed;
};

void
timespec_now(struct timespec *ts);

void
timespec_add_ms(struct timespec *ts, long ms);

void
timespec_add_ns(struct timespec *ts, long ns);

void
timeval_set(struct timeval *tv, double d);

struct timespec
timespec_diff(struct timespec *x, struct timespec *y);

void
timespec_adj(struct timespec *ts, double d);

int
timespec_cmp(struct timespec *a, struct timespec *b);

void
timespec_sub(struct timespec *a, struct timespec *b);

int
timespec_milliseconds(struct timespec *ts) ;

void
timespec_show(struct timespec *ts);

#endif/*__SYS_TIMESPEC_H__*/
