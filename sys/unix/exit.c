#include <sys/compiler.h>
#include <sys/cpu.h>

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>

_noreturn void
die(const char *fmt, ...) 
{
	va_list args;
	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
	exit(1);
}

_noreturn void
vdie(const char *fmt, va_list args)
{
	exit(1);
}
