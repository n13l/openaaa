/*                                                                              
 * The MIT License (MIT)                          General stack based functions 
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

#ifndef __SYS_MEM_STACK_H__
#define __SYS_MEM_STACK_H__

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <sys/compiler.h>
#include <sys/cpu.h>
#include <sys/decls.h>
#include <mem/alloc.h>

#define STK_MEM_CHUNK_SIZE 256

#define stk_alloc(S) \
({\
	void *_x = alloca(S); _x; \
})

#define stk_alloc_zero(S) \
({\
	void *_x = alloca(S); memset(_x, 0, S); _x; \
})

#define stk_strdup(s) \
({\
	const char *_s = (s); unsigned int _l = strlen(_s) + 1; \
	char *_x = alloca(_l); memcpy(_x, _s, _l); _x; \
})

#define stk_strndup(s, n) \
({\
	const char *_s = (s); unsigned int _l = strnlen(_s,(n)); \
	char *_x = alloca(_l+1); \
	memcpy(_x, _s, _l); _x[_l] = 0; _x; \
})

#define stk_strcat(s1, s2) \
({\
	const char *_s1 = (s1); const char *_s2 = (s2); \
	unsigned int _l1 = strlen(_s1); \
	unsigned int _l2 = strlen(_s2); \
	char *_x = alloca(_l1+_l2+1); memcpy(_x,_s1,_l1); \
	memcpy(_x + _l1,_s2,_l2+1); _x; \
})

#define stk_printf(...) \
({\
	unsigned int _l = stk_printf_size(__VA_ARGS__); \
	char *_x = (char *)alloca(_l); sprintf(_x, __VA_ARGS__); _x; \
})

#define stk_vprintf(f, args) \
({\
	unsigned int _l = stk_vprintf_size(f, args); \
	char *_x = alloca(_l); vsprintf(_x, f, args); _x; \
})

#define stk_strunesc(s) \
({\
	const char *_s = (const char *)(s); \
	char *_d = (char *)alloca(strlen(_s) + 1); str_unesc(_d, _s); _d; \
})

#define stk_decimal(addr, bytes) \
({ \
 	size_t __bytes = (size_t)(bytes); \
	char *__dst = alloca(((__bytes) * 5) + 1); \
	byte *__src = (byte *)addr; \
	char *_ds = __dst; \
	for (unsigned int __i = 0; __i < __bytes; __i++) { \
		char __num[6]; \
		snprintf(__num, sizeof(__num) - 1, "%d", (int)*__src++); \
 		if (__i) *_ds++ = ' '; \
		for (int __x = 0; __x < strlen(__num); __x++) \
			*_ds++ = __num[__x]; \
	} \
	*_ds++ = 0; \
	__dst; \
})

_unused static unsigned int
hex_make(unsigned int x)
{
	return (x < 10) ? (x + '0') : (x - 10 + 'a');
}

#define stk_hex_enc(addr, bytes) \
({\
 	byte *__src = (byte *)addr; \
 	size_t __bytes = (bytes); \
	byte *__x, *__dest = alloca(((__bytes) * 2) + 1); __x = __dest;\
	while (__bytes--) { \
		__dest[0] = hex_make(*__src >> 4); \
		__dest[1] = hex_make(*__src & 0x0f); \
		__dest += 2; __src++; \
	} \
	*__dest = 0; \
	__x; \
})

_unused static unsigned int 
hex_parse(unsigned int c)
{
	c = toupper(c);
	c -= '0';
	return (c < 10) ? c : (c - 7);
}

#define stk_hex_dec(addr, bytes) \
({\
 	byte *__src = addr; \
 	size_t __bytes = (bytes); \
 	byte *__x, *dest = alloca((__bytes) / 2); __x = dest;\
	while (__bytes--) { \
		*dest++ = (hex_parse(__src[0]) << 4) | hex_parse(__src[1]); \
 		__src += 2; \
	} \
	__x; \
})


_unused static unsigned int
stk_printf_size(const char *fmt, ...)
{
	unsigned int len = STK_MEM_CHUNK_SIZE;
	int __l;
	char *__buf = alloca(len);
	va_list args, args2;
	va_start(args, fmt);
	for (;;) {
		va_copy(args2, args);
		__l = vsnprintf(__buf, len, fmt, args2);
		va_end(args2);
		if (__l < 0) len *= 2; else { va_end(args); break; }
		__buf = alloca(len);
	}
	return __l + 1;
}

_unused static unsigned int
stk_vprintf_size(const char *fmt, va_list args)
{
	unsigned int len = STK_MEM_CHUNK_SIZE;
	int __l;
	char *buf = alloca(len);
	va_list args2;
	for (;;) {
		va_copy(args2, args);
		__l = vsnprintf(buf, len, fmt, args2);
		va_end(args2);
		if (__l < 0) len *= 2; else { va_end(args); break; }
		buf = alloca(len);
	}

	return __l + 1;
}

#endif/*__SYS_MEM_STACK_H__*/
