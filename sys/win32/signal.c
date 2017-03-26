#include <windows.h>

char *
strsignal(int sig)
{
	return "";
}

int
sigsetmask(int __mask)
{
	return -1;
}

int
sigprocmask (int __how, const sigset_t *__set, sigset_t *__oset)
{
	return -1;
}

int
sigaction (int __sig, const struct sigaction *__act, struct sigaction *__oact)
{
	return -1;
}

int
sigismember(const __sigset_t *sigset, int signo)
{
	return -1;
}

int
sigemptyset(__sigset_t *sigset)
{
	return -1;
}

int sigaddset (__sigset_t *sigset, int signo)
{
	return -1;
}

int
sigdelset(__sigset_t *sigset, int signo)
{
	return -1;
}
