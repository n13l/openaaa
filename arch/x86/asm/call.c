#include <sys/compiler.h>
#include <sys/cpu.h>
#include <sys/log.h>

#include <stdio.h>

#include <asm/instr.h>

__asm (
	".text;"
	"x86_call_naked:;"
	"movl $1,%eax;"
	"ret"
);

int
x86_call_naked(void);

int 
x86_call_overwrite(void *org, void *act)
{
	return 0;
}

int 
x86_call_interpose(void *org, void *act)
{
	return 0;
}
