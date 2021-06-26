/*
 * The MIT License (MIT)                                  (HEX) Base16 RFC-4648 
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
#include <string.h>
#include <ctype.h>
#include "b16.h"

static const u16 b16_prefix = '0' << 8 | 'x'; 

void
b16_encode(const u8 *src, size_t bytes, char *dst)
{
	static const char hextab[] = "0123456789abcdef";
	char *_ds = dst;
	const byte *in = (const byte*)src;
	for (unsigned i = 0; i < bytes; i++) {
		*_ds++ = hextab[in[i] >> 4];
		*_ds++ = hextab[in[i] & 0xf];
	} 
	*_ds = 0;
}

static unsigned int b16(unsigned int c)
{
	c = toupper(c); c -= '0';
	return (c < 10) ? c : (c - 7);
}

void
b16_decode(const char *str, size_t len, u8 *buf, size_t size)
{
	for (u8 *p = buf; size > (p - buf);) {
		if (len < 2)
			return;
		*p++ = (b16(str[0]) << 4) | b16(str[1]);
		len -= 2;
		str += 2;
	}
}

void
b16_decode_fast(const char *str, size_t len, u8 *buf)
{
	for (u8 *p = buf;;) {
		if (len < 2)
			return;
		*p++ = (b16(str[0]) << 4) | b16(str[1]);
		len -= 2;
		str += 2;
	}
}

void
b16_decode_adjust(const char *str, size_t len, u8 *buf)
{
	if (len > 1 && b16_prefix == *((u16*)str)) {
		str += 2; len -= 2;
	}

	for (u8 *p = buf;;) {
		if (len < 2)
			return;
		else if (*str == ' ' || *str == '-') {
			str++; len--;
		} else {
			*p++ = (b16(str[0]) << 4) | b16(str[1]);
			len -= 2;
			str += 2;
		}
	}
}

#ifdef TEST_VECTORS

static const char input1[] = "0xfafa";
static const char input2[] = "fa-fa";
static const char input3[] = "fa fa";
static const char input4[] = "fafa";

static const u8 expected1[] = {0xfa, 0xfa};

static inline void
test(const u8 *buf, unsigned int buf_len, const u8 *exp, unsigned int exp_len)
{
	fprintf(stderr, "\n expected size: %d %d\n", buf_len, exp_len);
	if (buf_len != exp_len)
		goto failed;
	if (memcmp(buf, exp, buf_len))
		goto failed;

	return;

failed:
	fprintf(stderr, "Test failed.\n");
	exit(EXIT_FAILURE);
}

int
main(int argc, char *argv[])
{
	u8 output[64];
	unsigned int size;

	printf("b16_decode validation test\n\n");
	size = b16_decode(input1, 6, output);
	test(output, size, expected1, sizeof(expected1));
	printf("\nAll tests passed.\n");
	return 0;
}

#endif
