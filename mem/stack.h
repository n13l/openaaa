/*                                                                              
 * The MIT License (MIT)                          Generic stack based functions 
 *                               Copyright (c) 2015 Daniel Kubec <niel@rtfm.cz> 
 *                                                                              
 * Permission is hereby granted, free of charge, to any person obtaining a copy 
 * of this software and associated documentation files (the "Software"),to deal 
 * in the Software without restriction, including without limitation the rights 
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell    
 * copies of the Software, and to permit persons to whom the Software is        
 * furnished to do so, subject to the following conditions:                     
 *                                                                              
 * The above copyright notice and this permission notice shall be included in   
 * all copies or substantial portions of the Software.                          
 *                                                                              
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR   
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,     
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE  
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER       
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,ARISING FROM, 
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN    
 * THE SOFTWARE.
 */

#ifndef MM_STACK_GENERIC_H__
#define MM_STACK_GENERIC_H__

#include <sys/compiler.h>
#include <sys/cpu.h>
#include <mem/alloc.h>
#include <mem/safe.h>
#include <mem/debug.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#ifndef MM_STACK_BLOCK_SIZE
#define MM_STACK_BLOCK_SIZE CPU_CACHE_LINE
#endif

#if defined __GNUC__
#ifndef alloca
# define alloca __builtin_alloca
#endif
#else
# include <alloca.h>
#endif

struct mm_stack {
	struct mm_savep save;
	void *avail, *final;
	unsigned int blocksize;
	unsigned int threshold;
	unsigned int index;
	unsigned int flags;
	unsigned int size;
};

/* Stack-based libc like functions */
#define sp_alloc(size) \
({\
	void *_X = alloca(size); \
	_X; \
})

/* Stack-based libc like functions */
#define sp_alloc_safe(sp, size) \
({\
	void *_X = alloca(size); \
	_X; \
})

/* call function prototype and alloca stack memory */
#define sp_cfn(fn, ...) \
({\
 	void *_X; \
	mem_stack_dbg("sp_cfn"); \
 	_X; \
})


#define sp_zalloc(size) \
({\
	void *_X = alloca(size); memset(_X, 0, size); _X; \
})

#define sp_strdup(string) \
({\
	unsigned int ____size = strlen(string) + 1; \
	char *_X = alloca(____size); memcpy(_X, string, ____size); _X; \
})

#define sp_strndup(string, size) \
({\
	const char *_S = (string); size_t _L = strnlen(_S,(size)); \
	char *_X = alloca(_L + 1); \
	memcpy(_X, _S, _L); _X[_L] = 0; _X; \
})

#define sp_strndupa(s, n) \
({							\
	const char *_O = (s);				\
	size_t _L = strnlen(_O, (n));			\
	char *_N = alloca(_L + 1);			\
	_N[_L] = '\0';					\
	memcpy(_N, _O, _L);				\
})
#define sp_printf(...) \
({\
	char *_S = (char *)alloca(sp_printfz((const char *)__VA_ARGS__)); \
        sprintf(_S, (const char *)__VA_ARGS__); _S; \
})

#define sp_vprintf(fmt, args) \
({\
	char *_X = alloca(sp_vprintfz(fmt,args)); vsprintf(_X, fmt, args);_X;\
})

/* Stack-based network layer functions */
#define sp_inet_ntop(af, addr) \
({\
	size_t _L = af == AF_INET ? INET_ADDRSTRLEN : INET6_ADDRSTRLEN;\
	char *_S = alloca(_L + 1);\
	const char *__D;\
	__D = inet_ntop(af, addr, _S, _L);\
	__D; \
})

_unused _noinline static unsigned int
sp_printfz(const char *fmt, ...)
{
	char *string = alloca(MM_STACK_BLOCK_SIZE);
	unsigned int avail =  MM_STACK_BLOCK_SIZE;

	va_list args, args2;
	va_start(args, fmt);

stack_avail:	
	va_copy(args2, args);
	int size = vsnprintf(string, avail, fmt, args2);
	va_end(args2);

	if (unlikely(size < 0)) {
		avail *= 2;
		string = alloca(avail);
		goto stack_avail;
	}

	va_end(args);
	return size + 1;
}

_unused _noinline static unsigned int 
sp_printfz_safe(struct mm_stack *sp, const char *fmt, ...)
{
	char *string = alloca(MM_STACK_BLOCK_SIZE);
	unsigned int avail =  MM_STACK_BLOCK_SIZE;

	va_list args, args2;
	va_start(args, fmt);

stack_avail:	
	va_copy(args2, args);
	int size = vsnprintf(string, avail, fmt, args2);
	va_end(args2);

	if (unlikely(size < 0)) {
		avail *= 2;
		string = alloca(avail);
		goto stack_avail;
	}

	va_end(args);
	return size + 1;
}


_unused _noinline static unsigned int 
sp_vprintfz(const char *fmt, va_list args)
{
	char *string = alloca(MM_STACK_BLOCK_SIZE);
	unsigned int avail  = MM_STACK_BLOCK_SIZE;
	va_list args2;

stack_avail:
	va_copy(args2, args);
	int size = vsnprintf(string, avail, fmt, args2);
	va_end(args2);

	if (unlikely(size < 0)) {
		avail *= 2; 
		string = alloca(avail);
		goto stack_avail;
	}

	va_end(args); 
	return size + 1;
}

/* Save version which check for the maximum limit for the current frame */
_unused _noinline static unsigned int 
sp_vprintfz_safe(struct mm_stack *sp, const char *fmt, va_list args)
{
	char *string = alloca(MM_STACK_BLOCK_SIZE);
	unsigned int avail  = MM_STACK_BLOCK_SIZE;
	va_list args2;

stack_avail:
	va_copy(args2, args);
	int size = vsnprintf(string, avail, fmt, args2);
	va_end(args2);

	if (unlikely(size < 0)) {
		avail *= 2; 
		string = alloca(avail);
		goto stack_avail;
	}

	va_end(args); 
	return size + 1;
}
#endif
