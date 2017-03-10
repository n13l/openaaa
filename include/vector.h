/*
 * Generic iterator
 *
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

#ifndef __GENERIC_VECTOR_H__
#define __GENERIC_VECTOR_H__

#include <stddef.h>

#define DEFINE_VECTOR(name, type) \
struct name { \
	    size_t elements; \
	    size_t capacity; \
	    type *items; \
};

#define vec_for_each(vec) 

#define vec_init(vec) __extension__ \
	(typeof(vec)){ .elements = 0, .capacity = 0, .data = NULL }

#define vec_begin(vec)
#define vec_end(vec)
#define vec_size(vec)
#define vec_capacity(vec)
#define vec_resize(vec)
#define vec_reserve(vec)
#define vec_push(vec)
#define vec_pop(vec)
#define vec_pushback(vec)
#define vec_popback(vec)

#endif/*__VECTOR_FILE_LIB_H__*/
