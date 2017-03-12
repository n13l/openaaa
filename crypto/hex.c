/*
 * The MIT License (MIT)                         (PRF) A Pseudo-Random Function 
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

#include <sys/compiler.h>
#include <crypto/hex.h>
#include <ctype.h>

static const char hextab[] = "0123456789abcdef";\

static unsigned int 
hexp(unsigned int c)
{
	c = toupper(c);
	c -= '0';
	return (c < 10) ? c : (c - 7);
}

char *
memhex(char *src, size_t bytes, char *dst)
{
	char *_ds = dst;
	const byte *in = (const byte*)src;
	for (unsigned i = 0; i < bytes; i++) {
		*_ds++ = hextab[in[i] >> 4];
		*_ds++ = hextab[in[i] & 0xf];
	} 
	*_ds = 0;
	return dst;
}

char *
hexmem(char *src, size_t bytes, char *dst)
{
	size_t len = bytes;
	char *dest = dst;
	while (bytes--) { 
		*dest++ = (hexp(src[0]) << 4) | hexp(src[1]);
		src += 2;
       	} 
	dst[(len * 2) +1] = 0; 
	return dst;
}
