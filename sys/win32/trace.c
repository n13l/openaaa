#include <windows.h>
#include <imagehlp.h>

void
win32_stacktrace(CONTEXT *ctx)
{
	SymInitialize(GetCurrentProcess(), 0, 1);

	STACKFRAME frame = {
		.AddrPC.Offset    = ctx->Eip,
		.AddrPC.Mode      = AddrModeFlat,
		.AddrStack.Offset = ctx->Esp,
		.AddrStack.Mode   = AddrModeFlat,
		.AddrFrame.Offset = ctx->Ebp,
		.AddrFrame.Mode   = AddrModeFlat
	};

	while(StackWalk(IMAGE_FILE_MACHINE_I386,
		GetCurrentProcess(), GetCurrentThread(),
		&frame, ctx, 0, SymFunctionTableAccess, SymGetModuleBase,0))
		addr2line(icky_global_program_name, (void*)frame.AddrPC.Offset);

	SymCleanup(GetCurrentProcess());
}

void
crypto_lookup(void)
{
}
