#include <sys/compiler.h>
#include <sys/cpu.h>
#include <asm/udis86.h>
#include <asm/cache.h>
#include <asm/instr.h>

#include <inttypes.h>
#include <stdint.h>

static const char* 
x86_sym_resolve(struct ud *u, u64 addr, s64 *offset)
{
	*offset = addr - 0x15;
	return "target";
}

static inline void
x86_instr_dump2(struct ud *u)
{
	arch_dbg("%016" PRIxPTR "%-16s %s", (intptr_t)ud_insn_off(u), 
	         ud_insn_hex(u), ud_insn_asm(u)); 
}

int
x86_branch_prologue(struct x86_prologue *prologue, void *code, s16 require)
{
	arch_dbg("prologue addr=%p require=%d", code, (int)require);

	ud_t obj;
	ud_init(&obj);
	ud_set_mode(&obj, 64);
	ud_set_input_buffer(&obj, code, 64);
	ud_set_syntax(&obj, UD_SYN_INTEL);
	ud_set_sym_resolver(&obj, &x86_sym_resolve);

	for (int i = 0, total = 0; require > 0; i++) {
		if (!ud_disassemble(&obj))
			return -1;

		int len = ud_insn_len(&obj);

		prologue->instr[i] = (struct x86_instr) {
			.code = code, .size = len
		};

		require -= len;
		total   += len;
		code    += len;

		x86_instr_dump2(&obj);
		prologue->size = total;
	}

	arch_dbg("prologue code=%p size=%u", code, prologue->size);

	return 0;
}
