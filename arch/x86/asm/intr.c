#include <sys/compiler.h>
#include <stdlib.h>
#include <stdio.h>

void
x86_call_intr_vec(byte val)
{   	
	byte assembly[6];
	assembly[0] = 0xCC; /* INT 3 */
	assembly[1] = 0x90; /* NOP   */
	assembly[2] = 0xC2; /* RET   */
	assembly[3] = 0x00;
	assembly[4] = 0x00;

	if (val != 3) {
		assembly[0] = 0xCD;
		assembly[1] = val;
	}

	__asm("call *%0" : : "r"(assembly));
}
