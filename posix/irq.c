/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2015 Daniel Kubec <niel@rtfm.cz> 
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

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <posix/irq.h>

/* block mask for the signals */
__thread sigset_t blk_mask;
__thread sigset_t irq_mask;

__thread volatile sig_atomic_t __shutdown = 0;
__thread volatile sig_atomic_t __restart  = 0;

/* 
 * The sigthreadmask subroutine is used to examine or change the signal mask 
 * of the calling thread. The sigprocmask subroutine must not be used in a 
 * multi-threaded process.
 */

#ifdef THREADS
#define irqmask sigthreadmask
#else
#define irqmask sigprocmask
#endif

void
irq_handler(int signo, siginfo_t *info, void *context)
{
	switch (signo) {
	case SIGTERM: __shutdown = 1; break;
	case SIGHUP:  __restart  = 1; break;
	}
}

int
irq_pending(int signo)
{
	switch (signo) {
	case SIGTERM: return __shutdown;
	case SIGHUP:  return __restart;
	default:      return -EINVAL;
	}
}
void
irq_default(void)
{
	struct sigaction sa = {
		.sa_flags     = SA_SIGINFO,
		.sa_mask      = blk_mask,
		.sa_sigaction = irq_handler
	};

	/* setup default action for interest signals */
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT,  &sa, NULL);
	sigaction(SIGHUP,  &sa, NULL);
	sigaction(SIGUSR1, &sa, NULL);


}

void
irq_constructor(void)
{
	signal(SIGPIPE, SIG_IGN);
       	/* block usefull signals before we are ready to use them */
	sig_disable(SIGUSR1);
	sig_disable(SIGHUP);

	/* block mask for other signals while handler runs. */
	sigemptyset(&blk_mask);
	sigaddset(&blk_mask, SIGTERM);
	sigaddset(&blk_mask, SIGINT);
	sigaddset(&blk_mask, SIGHUP);
	sigaddset(&blk_mask, SIGUSR1);

	irq_default();
}

void
sig_disable(int sig)
{
	sigset_t mask;
	sigemptyset(&mask);
	sigaddset(&mask, sig);
	irqmask(SIG_BLOCK, &mask, NULL);
}

void
sig_enable(int sig)
{
	sigset_t mask;
	sigemptyset(&mask);
	sigaddset(&mask, sig);
	irqmask(SIG_UNBLOCK, &mask, NULL);
}

void
irq_enable(void)
{
	irqmask(SIG_SETMASK, NULL, &irq_mask);
	irqmask(SIG_UNBLOCK, &irq_mask, NULL);
}

void
irq_disable(void)
{
	irqmask(SIG_BLOCK, &blk_mask, &irq_mask);
}
