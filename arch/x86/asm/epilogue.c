#include <sys/compiler.h>
#include <sys/cpu.h>
#include <asm/udis86.h>
#include <asm/cache.h>
#include <asm/instr.h>

int
x86_epilogue(u8 *code, u16 require, struct x86_prologue *x86_prologue)
{
	ud_t obj;
	ud_init(&obj);
	ud_set_mode(&obj, 64);
	ud_set_input_buffer(&obj, code, 64);

	for (int index = 0, total = 0; require > 0; ) {
		if (!ud_disassemble(&obj))
			return -1;

		int len = ud_insn_len(&obj);
		require -= len;
		total   += len;

		x86_prologue->instr[index].size = len;

		printf("asm: %s\n", ud_insn_asm(&obj));

		//if (sizes) sizes[index] = eaten;
		index += 1;
		//count = index;
	}

	return 0;
}
