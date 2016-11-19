#include <windows.h>
#include <stdio.h>

LONG WINAPI
exception_handler(EXCEPTION_POINTERS *ExceptionInfo)
{
switch(ExceptionInfo->ExceptionRecord->ExceptionCode)
{
case EXCEPTION_ACCESS_VIOLATION:
fputs("Error: EXCEPTION_ACCESS_VIOLATION\n", stderr);
break;
case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
fputs("Error: EXCEPTION_ARRAY_BOUNDS_EXCEEDED\n", stderr);
break;
case EXCEPTION_BREAKPOINT:
fputs("Error: EXCEPTION_BREAKPOINT\n", stderr);
break;
case EXCEPTION_DATATYPE_MISALIGNMENT:
fputs("Error: EXCEPTION_DATATYPE_MISALIGNMENT\n", stderr);
break;
case EXCEPTION_FLT_DENORMAL_OPERAND:
fputs("Error: EXCEPTION_FLT_DENORMAL_OPERAND\n", stderr);
break;
case EXCEPTION_FLT_DIVIDE_BY_ZERO:
fputs("Error: EXCEPTION_FLT_DIVIDE_BY_ZERO\n", stderr);
break;
case EXCEPTION_FLT_INEXACT_RESULT:
fputs("Error: EXCEPTION_FLT_INEXACT_RESULT\n", stderr);
break;
case EXCEPTION_FLT_INVALID_OPERATION:
fputs("Error: EXCEPTION_FLT_INVALID_OPERATION\n", stderr);
break;
case EXCEPTION_FLT_OVERFLOW:
fputs("Error: EXCEPTION_FLT_OVERFLOW\n", stderr);
break;
case EXCEPTION_FLT_STACK_CHECK:
fputs("Error: EXCEPTION_FLT_STACK_CHECK\n", stderr);
break;
case EXCEPTION_FLT_UNDERFLOW:
fputs("Error: EXCEPTION_FLT_UNDERFLOW\n", stderr);
break;
case EXCEPTION_ILLEGAL_INSTRUCTION:
fputs("Error: EXCEPTION_ILLEGAL_INSTRUCTION\n", stderr);
break;
case EXCEPTION_IN_PAGE_ERROR:
fputs("Error: EXCEPTION_IN_PAGE_ERROR\n", stderr);
break;
case EXCEPTION_INT_DIVIDE_BY_ZERO:
fputs("Error: EXCEPTION_INT_DIVIDE_BY_ZERO\n", stderr);
break;
case EXCEPTION_INT_OVERFLOW:
fputs("Error: EXCEPTION_INT_OVERFLOW\n", stderr);
break;
case EXCEPTION_INVALID_DISPOSITION:
fputs("Error: EXCEPTION_INVALID_DISPOSITION\n", stderr);
break;
case EXCEPTION_NONCONTINUABLE_EXCEPTION:
fputs("Error: EXCEPTION_NONCONTINUABLE_EXCEPTION\n", stderr);
break;
case EXCEPTION_PRIV_INSTRUCTION:
fputs("Error: EXCEPTION_PRIV_INSTRUCTION\n", stderr);
break;
case EXCEPTION_SINGLE_STEP:
fputs("Error: EXCEPTION_SINGLE_STEP\n", stderr);
break;
case EXCEPTION_STACK_OVERFLOW:
fputs("Error: EXCEPTION_STACK_OVERFLOW\n", stderr);
break;
default:
fputs("Error: Unrecognized Exception\n", stderr);
break;
}
	    fflush(stderr);
if (EXCEPTION_STACK_OVERFLOW != ExceptionInfo->ExceptionRecord->ExceptionCode)
{
windows_print_stacktrace(ExceptionInfo->ContextRecord);
}
else
{
addr2line(icky_global_program_name, (void*)ExceptionInfo->ContextRecord->Eip);
}
		 
return EXCEPTION_EXECUTE_HANDLER;
}
 
void
set_signal_handler()
{
	SetUnhandledExceptionFilter(windows_exception_handler);
}
