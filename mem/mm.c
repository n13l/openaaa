/*
 * High performance, generic and type-safe memory management
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2015, 2016, 2017, 2018, 2019       Daniel Kubec <niel@rtfm.cz> 
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
#include <sys/cpu.h>
#include <list.h>
#include <mem/alloc.h>

void *
mm_alloc(struct mm *mm, size_t size)
{
	return mm->alloc(mm, size);
}

void *
mm_zalloc(struct mm *mm, size_t size)
{
	void *addr = mm->alloc(mm, size);
	memset(addr, 0, size);
	return addr;
}

void *
mm_realloc(struct mm *mm, void *addr, size_t size)
{
	return mm->realloc(mm, addr, size);
}

void
mm_free(struct mm *mm, void *addr)
{
	if (mm->free)
		mm->free(mm, addr);
}

char *
mm_strmem(struct mm *mm, const char *str, size_t len)
{
	char *s = (char *)mm->alloc(mm, len + 1);
	memcpy(s, str, len);
	s[len] = 0;
	return s;
}

void *
mm_memdup(struct mm *mm, void *ptr, size_t len)
{
	void *s = (void *)mm->alloc(mm, len);
	memcpy(s, ptr, len);
	return s;
}

char *
mm_strdup(struct mm *mm, const char *str)
{
	size_t len = strlen(str);
	char *s = (char *)mm->alloc(mm, len + 1);
	memcpy(s, str, len);
	s[len] = 0;
	return s;
}

char *
mm_strndup(struct mm *mm, const char *str, size_t len)
{
	char *s = (char *)mm->alloc(mm, len + 1);
	memcpy(s, str, len);
	s[len] = 0;
	return s;
}

char *
mm_vprintf(struct mm *mm, const char *fmt, va_list args)
{
	int len = vprintfza(fmt, args);
	char *p = mm->alloc(mm, len + 1);
	vsnprintf(p, len, fmt, args);
	return p;
}

char *
mm_printf(struct mm *mm, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	char *addr = mm_vprintf(mm, fmt, args);
	va_end(args);
	return addr;
}

char *
mm_strcat(struct mm *mm, ...)
{
	va_list args, a;
	va_start(args, mm);
	va_copy(a, args);

	char *x, *y, *s;
	unsigned int len = 0, c = 0;
	while ((x = va_arg(a, char *)))
		c++;
	va_end(a);
	va_copy(a, args);

	size_t sizes[c];
	c = 0;
	while ((x = va_arg(a, char *)))
		len += sizes[c++] = strlen(x);
	y = s = (char *)mm->alloc(mm, len + 1);
	va_end(a);

	c = 0;
	while ((x = va_arg(args, char *))) {
		memcpy(y, x, sizes[c]);
		y += sizes[c++];
	}
	
	*y = 0;
	va_end(args);
	return s;
}
	
char *
mm_fsize(struct mm *mm, u64 num)
{
	if (num < 1 << 10)
		return mm_printf(mm, "%dB", (int)num);
	else if (num < 10 << 10)
		return mm_printf(mm, "%.1fK", (double)num/(1<<10));
	else if (num < 1 << 20)
		return mm_printf(mm, "%dK", (int)(num/(1<<10)));
	else if (num < 10 << 20)
		return mm_printf(mm, "%.1fM", (double)num/(1<<20));
	else if (num < 1 << 30)
		return mm_printf(mm, "%dM", (int)(num/(1<<20)));
	else if (num < (u64)10 << 30)
		return mm_printf(mm, "%.1fG", (double)num/(1<<30));
	else if (num != ~(u64)0)
		return mm_printf(mm, "%dG", (int)(num/(1<<30)));

	return "unknown";
}
