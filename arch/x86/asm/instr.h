#ifndef	__X86_INSTR_H__
#define __X86_INSTR_H__

#include <sys/compiler.h>
#include <sys/cpu.h>
#include <sys/types.h>
#include <unix/list.h>

#define X86_PROLOGUE_MAX 64
#define X86_EPILOGUE_MAX 64

#define I_NOP 0x90

#define arch_dbg(fmt, ...) \
	printf("x86: " fmt "\n", ## __VA_ARGS__)

struct arch_module {
	struct mempool *mp;
};

struct x86_asm;

struct x86_instr {
	void *code;
	unsigned int size;
};

struct x86_instr_block {
	struct node n;
	struct x86_instr instr;
};

struct arch_instr_n {
	struct node n;
	void *code;
	unsigned int size;
};

struct arch_prologue {
	struct list instr;
	void *addr;
	unsigned int size;

};

struct x86_prologue {
	struct x86_instr instr[X86_PROLOGUE_MAX];
	u8 *code;
	u8 size;
};

struct arch_trampoline_struct {
	struct node n;
	struct arch_module   module;
	struct arch_prologue prologue;
	const char *name;
};

#define arch_instr_size x86_instr_size
#define arch_trampoline x86_trampoline

int x86_instr_size(void *code);
int x86_instr_dump(void *code);
int x86_instr_block(struct mempool *mp, void *code, int require);

/* creates a function descriptor for a piece of generated code */
int arch_ftnptr(void *addr, int type);

#define arch_interpose x86_interpose
#define arch_call_interpose x86_call_interpose
#define arch_call_overwrite x86_call_overwrite

int x86_call_interpose(void *org, void *act);
int c86_call_overwrite(void *arg, void *act);

int                                                                             
x86_branch_prologue(struct x86_prologue *x86_prologue, void *code, s16 require);

struct arch_trampoline *
mach_trampoline(void *org, void *act);

int
x86_interpose(void *org, void *act);

#endif
