#ifndef __ARCH_X86_ATOMIC_MOV64_H__
#define __ARCH_X86_ATOMIC_MOV64_H__

#include <sys/compiler.h>
#include <sys/cpu.h>

#if defined(X86_32)
void atomic_mov64(u64 *addr, u64 value);;

__asm(
".text;"
".align 2, 0x90;"
"atomic_mov64:;"
"	pushl %ebp;"
"	movl %esp, %ebp;"
"	pushl %esi;"
"	pushl %ebx;"
"	pushl %ecx;"
"	pushl %eax;"
"	pushl %edx;"
"	mov   8(%ebp), %esi;"
"	mov  12(%ebp), %ebx;"
"	mov  16(%ebp), %ecx;"
"	mov    (%esi), %eax;"
"	mov   4(%esi), %edx;"
"	lock; cmpxchg8b	(%esi);"
"	popl %edx;"
"	popl %eax;"
"	popl %ecx;"
"	popl %ebx;"
"	popl %esi;"
"	popl %ebp;"
"	ret"
);
#endif
#ifdef __x86_64__
static inline void
atomic_mov64(u64 *addr, u64 value)
{
	*addr = value;
}
#endif

#endif
