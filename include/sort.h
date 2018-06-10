/*
 * Generic sort for containers
 *
 * The MIT License (MIT)         Copyright (c) 2018 Daniel Kubec <niel@rtfm.cz> 
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

#ifndef __CCE_GENERIC_SORT_H__
#define __CCE_GENERIC_SORT_H__

#include <sys/compiler.h>

/**
 * bubble_sort  - sort list 
 *
 * @list:       the your list.
 * @fn:	        the type safe comparator
 * @type:       the optional structure type
 * @member:	the optional name of the node within the struct.
 */

#define bubble_sort(list, ...) \
	va_dispatch(bubble_sort_asc,__VA_ARGS__)(list,__VA_ARGS__)

/**
 * bubble_sort_asc  - sort list 
 *
 * @list:       the your list.
 * @fn:	        the type safe comparator
 * @type:       the optional structure type
 * @member:	the optional name of the node within the struct.
 */

#define bubble_sort_asc(list, ...) \
	va_dispatch(bubble_sort_asc,__VA_ARGS__)(list,__VA_ARGS__)
#define bubble_sort_asc1(list, __cmp_fn) \
        for (struct node *z, *y, *x = list_head(list); x; ) { \
                for (z = y = x; (y = list_next(list, y)); )   \
                        if (__cmp_fn(y, z) < 0) z = y; \
                if (x == z) \
			x = list_next(list, x); \
		else { \
			list_del(z); list_add_before(z, x); \
		} \
        }
#define bubble_sort_asc3(list, __cmp_fn, type, member) \
        for (struct node *z, *y, *x = list_head(list); x; ) { \
                for (z = y = x; (y = list_next(list, y)); )   \
                        if (__cmp_fn(__container_of(y, type, member), \
			             __container_of(z, type, member)) < 0) \
				z = y; \
                if (x == z) \
                        x = list_next(list, x); \
                else { \
                        list_del(z); list_add_before(z, x); \
                } \
        }

/**
 * bubble_sort_dsc  - sort list 
 *
 * @list:       the your list.
 * @fn:	        the type safe comparator
 * @type:       the optional structure type
 * @member:	the optional name of the node within the struct.
 */

#define bubble_sort_dsc(list, ...) \
	va_dispatch(bubble_sort_dsc,__VA_ARGS__)(list,__VA_ARGS__)
#define bubble_sort_dsc1(list, __cmp_fn) \
        for (struct node *z, *y, *x = list_head(list); x; ) { \
                for (z = y = x; (y = list_next(list, y)); )   \
                        if (__cmp_fn(y, z) > 0) z = y; \
                if (x == z) \
                        x = list_next(list, x); \
                else { \
                        list_del(z); list_add_before(z, x); \
                } \
        }
#define bubble_sort_dsc3(list, cmp_fn, __type, member) \
        for (struct node *z, *y, *x = list_head(list); x; ) { \
                for (z = y = x; (y = list_next(list, y)); )   \
                        if (cmp_fn(__container_of(y, __type, member), \
			           __container_of(z, __type, member)) > 0) \
				z = y; \
                if (x == z) \
                        x = list_next(list, x); \
                else { \
                        list_del(z); list_add_before(z, x); \
                } \
        }


#endif/*__CCE_GENERIC_SORT_H__*/
