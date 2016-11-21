#include <windows.h>
#include <stdio.h>
#include <sys/log.h>

const char *progname = "";

int
addr2line(char const * const name, void const * const addr)
{
	char cmd[512] = {0};
	   
#ifdef __APPLE__
	snprintf(cmd, sizeof(cmd) - 1, "atos -o %.256s %p", name, addr); 
#else
	snprintf(cmd, sizeof(cmd) - 1, "addr2line -f -p -e %.256s %p", name, addr); 
#endif
	return system(cmd);
}

LONG WINAPI
exception_handler(EXCEPTION_POINTERS *info)
{
	switch(info->ExceptionRecord->ExceptionCode) {
	case EXCEPTION_ACCESS_VIOLATION:
		error("EXCEPTION_ACCESS_VIOLATION");
		break;
	case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
		error("EXCEPTION_ARRAY_BOUNDS_EXCEEDED");
		break;
	case EXCEPTION_BREAKPOINT:
		error("EXCEPTION_BREAKPOINT");
		break;
	case EXCEPTION_DATATYPE_MISALIGNMENT:
		error("EXCEPTION_DATATYPE_MISALIGNMENT");
		break;
	case EXCEPTION_FLT_DENORMAL_OPERAND:
		error("EXCEPTION_FLT_DENORMAL_OPERAND");
		break;
	case EXCEPTION_FLT_DIVIDE_BY_ZERO:
		error("EXCEPTION_FLT_DIVIDE_BY_ZERO");
		break;
	case EXCEPTION_FLT_INEXACT_RESULT:
		error("EXCEPTION_FLT_INEXACT_RESULT");
		break;
	case EXCEPTION_FLT_INVALID_OPERATION:
		error("EXCEPTION_FLT_INVALID_OPERATION");
		break;
	case EXCEPTION_FLT_OVERFLOW:
		error("EXCEPTION_FLT_OVERFLOW");
		break;
	case EXCEPTION_FLT_STACK_CHECK:
		error("EXCEPTION_FLT_STACK_CHECK");
		break;
	case EXCEPTION_FLT_UNDERFLOW:
		error("EXCEPTION_FLT_UNDERFLOW");
		break;
	case EXCEPTION_ILLEGAL_INSTRUCTION:
		error("EXCEPTION_ILLEGAL_INSTRUCTION");
		break;
	case EXCEPTION_IN_PAGE_ERROR:
		error("EXCEPTION_IN_PAGE_ERROR");
		break;
	case EXCEPTION_INT_DIVIDE_BY_ZERO:
		error("EXCEPTION_INT_DIVIDE_BY_ZERO");
		break;
	case EXCEPTION_INT_OVERFLOW:
		error("EXCEPTION_INT_OVERFLOW");
		break;
	case EXCEPTION_INVALID_DISPOSITION:
		error("EXCEPTION_INVALID_DISPOSITION");
		break;
	case EXCEPTION_NONCONTINUABLE_EXCEPTION:
		error("EXCEPTION_NONCONTINUABLE_EXCEPTION");
		break;
	case EXCEPTION_PRIV_INSTRUCTION:
		error("EXCEPTION_PRIV_INSTRUCTION");
		break;
	case EXCEPTION_SINGLE_STEP:
		error("EXCEPTION_SINGLE_STEP");
		break;
	case EXCEPTION_STACK_OVERFLOW:
		error("EXCEPTION_STACK_OVERFLOW");
		break;
	default:
		error("Unrecognized Exception");
		break;
	}

	if (EXCEPTION_STACK_OVERFLOW != info->ExceptionRecord->ExceptionCode)
		win32_stacktrace(info->ContextRecord);
	else
		addr2line(progname, (void*)info->ContextRecord->Eip);
		 
	return EXCEPTION_EXECUTE_HANDLER;
}
 
void
set_signal_handler(void)
{
	SetUnhandledExceptionFilter(exception_handler);
}
