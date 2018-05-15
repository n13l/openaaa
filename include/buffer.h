/*
 * The MIT License (MIT)         Copyright (c) 2017 Daniel Kubec <niel@rtfm.cz> 
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
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef __GENERIC_BYTEBUFFERS_H__
#define __GENERIC_BYTEBUFFERS_H__

#include <sys/compiler.h>

/* opaque info for memory allocation */
struct mm;

/* byte buffer */
struct bb {
	byte *addr;
	size_t len;
};

struct mb {
	size_t capacity;
	struct mm *mm;
	union { struct bb bb; };

};

#define bb_init(__addr, __size) \
  ({ struct bb __bb = (struct bb){.addr = __addr, .len = __size }; __bb; }) 

/*
 * Concatenate a string to an bbuf buffer
 *
 * @param bb pointer to the bbuf struct
 * @param str the string to append; must be at least len bytes long
 * @param len the number of characters of *str to concatenate to the buf
 * @note bb->len will be set to the length of the new string
 * @note bb->buf will be null-terminated
 */

void bb_strmemcat(struct bb *bb, const char *str, size_t len);

/*
 * Concatenate a string to an bbuf buffer
 *
 * @param bb pointer to the bbuf struct
 * @param str the string to append
 * @note bb->len will be set to the length of the new string
 */

#define bb_strcat(bb, str) bb_strmemcat(bb, str, strlen(str))

static inline void *
bb_unpack(struct bb *bb, size_t size)
{
	byte *p = (byte *)bb->addr;
	bb->addr += size;
	bb->len  -= size;
	return p;
}

static inline char *
bstrtok(char *buf, ssize_t *size, char *sep, char **ptr)
{
        char *p = buf = buf ? buf: *ptr;
        for (; *size; p++, (*size)--) {
                if (*p != *sep)
                        continue;
                *p = 0;
                *ptr = p + 1;
                (*size)--;
                return buf;
        }

        if (p == buf)
                return NULL;
        else
                *p = 0;
        return buf;
}

#endif/*__BYTEBUFFER_FILE_LIB_H__*/
