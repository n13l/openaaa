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

#define SORT_ORDER_RND 0x01
#define SORT_ORDER_ASC 0x02
#define SORT_ORDER_DSC 0x03

#ifndef SORT_MERGE_BOTTOM_UP_SHIFT
#define SORT_MERGE_BOTTOM_UP_SHIFT 9
#endif

/**
 * insert_sort
 *
 * sort container items in ascending order
 *
 * @self:       the instance
 * @prefix      the prefix of _first(), _next() and _move_before() methods
 * @cmp:        the type safe cmp
 * @type:       the optional structure type of container
 * @member:     the optional name of the node within the struct.
 *
 * container set requires _first(), _next(), _move_before() methods 
 *
 * Time complexity:  Θ(n^2) 
 * Space complexity: 0(1)
 *
 */

#define insert_sort(self,prefix, ...) \
	va_dispatch(insert_sort_asc,__VA_ARGS__)(self,prefix,__VA_ARGS__)

/**
 * insert_sort_asc
 *
 * sort container items in ascending order
 *
 * @self:       the instance
 * @prefix      the prefix of _first(), _next() and _move_before() methods
 * @cmp:        the type safe cmp
 * @type:       the optional structure type of container
 * @member:     the optional name of the node within the struct.
 *
 * container set requires defined _first(), _next(), _move_before() methods
 *
 */

#define insert_sort_asc(self,prefix,...) \
	va_dispatch(insert_sort_asc,__VA_ARGS__)(self,prefix,__VA_ARGS__)
#define insert_sort_asc1(self,prefix,cmp) \
({ \
	for (prefix##_node *z, *y, *x = prefix##_first(self); x; ) { \
		for (z = y = x; (y = prefix##_next(self, y)); )   \
			if (cmp(y, z) < 0) z = y; \
		if (x == z) \
			x = prefix##_next(self, x); \
		else \
			prefix##_move_before(z, x); \
	} \
})
#define insert_sort_asc3(self,prefix,cmp,type,member) \
({ \
	for (prefix##_node *z, *y, *x = prefix##_first(self); x; ) { \
		for (z = y = x; (y = prefix##_next(self, y)); )   \
			if (container_cmp(cmp, y, z, type, member) < 0) z = y;\
		if (x == z) \
			x = prefix##_next(self, x); \
		else \
			prefix##_move_before(z, x); \
	} \
})

/**
 * insert_sort_dsc
 *
 * sort container items in descending order
 *
 * @self:       the instance
 * @prefix      the prefix of _first(), _next() and _move_before() methods
 * @cmp:        the type safe cmp
 * @type:       the optional structure type of container
 * @member:     the optional name of the node within the struct.
 *
 * container set requires defined _first(), _next(), _move_before() methods
 * 
 */

#define insert_sort_dsc(self,prefix, ...) \
	va_dispatch(insert_sort_dsc,__VA_ARGS__)(self,prefix,__VA_ARGS__)
#define insert_sort_dsc1(self,prefix,cmp) \
({ \
	for (prefix##_node *z, *y, *x = prefix##_first(self); x; ) { \
		for (z = y = x; (y = prefix##_next(self, y)); )   \
			if (cmp(y, z) > 0) z = y; \
		if (x == z) \
			x = prefix##_next(self, x); \
		else \
			prefix##_move_before(z, x); \
	} \
})
#define insert_sort_dsc3(self,prefix,cmp,type,member) \
({ \
	for (prefix##_node *z, *y, *x = prefix##_first(self); x; ) { \
		for (z = y = x; (y = prefix##_next(self, y)); )   \
			if (container_cmp(cmp, y, z, type, member) > 0) z = y;\
		if (x == z) \
			x = prefix##_next(self, x); \
		else \
			prefix##_move_before(z, x); \
	} \
})

/**
 * select_sort
 *
 * sort container items in ascending order
 *
 * @self:       the instance
 * @prefix      the prefix of _first(), _next() and _move_before() methods
 * @cmp:        the type safe cmp
 * @type:       the optional structure type of container
 * @member:     the optional name of the node within the struct.
 *
 * container set requires _first(), _next(), _move_before() methods 
 *
 * Time complexity:  Θ(n^2) 
 * Space complexity: 0(1)
 *
 */

#define select_sort(self,prefix, ...) \
	va_dispatch(select_sort_asc,__VA_ARGS__)(self,prefix,__VA_ARGS__)

/**
 * select_sort_asc
 *
 * sort container items in ascending order
 *
 * @self:       the instance
 * @prefix      the prefix of _first(), _next() and _move_before() methods
 * @cmp:        the type safe cmp
 * @type:       the optional structure type of container
 * @member:     the optional name of the node within the struct.
 *
 * container set requires defined _first(), _next(), _move_before() methods
 *
 */

#define select_sort_asc(self,prefix,...) \
	va_dispatch(select_sort_asc,__VA_ARGS__)(self,prefix,__VA_ARGS__)
#define select_sort_asc1(self,prefix,cmp) \
({ \
	for (prefix##_node *z, *y, *x = prefix##_first(self); x; ) { \
		for (z = y = x; (y = prefix##_next(self, y)); )   \
			if (cmp(y, z) < 0) z = y; \
		if (x == z) \
			x = prefix##_next(self, x); \
		else \
			prefix##_move_before(z, x); \
	} \
})
#define select_sort_asc3(self,prefix,cmp,type,member) \
({ \
	for (prefix##_node *z, *y, *x = prefix##_first(self); x; ) { \
		for (z = y = x; (y = prefix##_next(self, y)); )   \
			if (container_cmp(cmp, y, z, type, member) < 0) z = y;\
		if (x == z) \
			x = prefix##_next(self, x); \
		else \
			prefix##_move_before(z, x); \
	} \
})

/**
 * select_sort_dsc
 *
 * sort container items in descending order
 *
 * @self:       the instance
 * @prefix      the prefix of _first(), _next() and _move_before() methods
 * @cmp:        the type safe cmp
 * @type:       the optional structure type of container
 * @member:     the optional name of the node within the struct.
 *
 * container set requires defined _first(), _next(), _move_before() methods
 * 
 */

#define select_sort_dsc(self,prefix, ...) \
	va_dispatch(select_sort_dsc,__VA_ARGS__)(self,prefix,__VA_ARGS__)
#define select_sort_dsc1(self,prefix,cmp) \
({ \
	for (prefix##_node *z, *y, *x = prefix##_first(self); x; ) { \
		for (z = y = x; (y = prefix##_next(self, y)); )   \
			if (cmp(y, z) > 0) z = y; \
		if (x == z) \
			x = prefix##_next(self, x); \
		else \
			prefix##_move_before(z, x); \
	} \
})
#define select_sort_dsc3(self,prefix,cmp,type,member) \
({ \
	for (prefix##_node *z, *y, *x = prefix##_first(self); x; ) { \
		for (z = y = x; (y = prefix##_next(self, y)); )   \
			if (container_cmp(cmp, y, z, type, member) > 0) z = y;\
		if (x == z) \
			x = prefix##_next(self, x); \
		else \
			prefix##_move_before(z, x); \
	} \
})

/**
 * bubble_sort
 *
 * sort container items in ascending order
 *
 * @self:       the instance
 * @prefix      the prefix of _first(), _next() and _move_before() methods
 * @cmp:        the type safe cmp
 * @type:       the optional structure type of container
 * @member:     the optional name of the node within the struct.
 *
 * container set requires _first(), _next(), _move_before() methods 
 *
 * Time complexity:  Θ(n^2) 
 * Space complexity: 0(1)
 *
 */

#define bubble_sort(self,prefix, ...) \
	va_dispatch(bubble_sort_asc,__VA_ARGS__)(self,prefix,__VA_ARGS__)

/**
 * bubble_sort_asc
 *
 * sort container items in ascending order
 *
 * @self:       the instance
 * @prefix      the prefix of _first(), _next() and _move_before() methods
 * @cmp:        the type safe cmp
 * @type:       the optional structure type of container
 * @member:     the optional name of the node within the struct.
 *
 * container set requires defined _first(), _next(), _move_before() methods
 *
 */

#define bubble_sort_asc(self,prefix,...) \
	va_dispatch(bubble_sort_asc,__VA_ARGS__)(self,prefix,__VA_ARGS__)
#define bubble_sort_asc1(self,prefix,cmp) \
({ \
	for (prefix##_node *z, *y, *x = prefix##_first(self); x; ) { \
		for (z = y = x; (y = prefix##_next(self, y)); )   \
			if (cmp(y, z) < 0) z = y; \
		if (x == z) \
			x = prefix##_next(self, x); \
		else \
			prefix##_move_before(z, x); \
	} \
})
#define bubble_sort_asc3(self,prefix,cmp,type,member) \
({ \
	for (prefix##_node *z, *y, *x = prefix##_first(self); x; ) { \
		for (z = y = x; (y = prefix##_next(self, y)); )   \
			if (container_cmp(cmp, y, z, type, member) < 0) z = y;\
		if (x == z) \
			x = prefix##_next(self, x); \
		else \
			prefix##_move_before(z, x); \
	} \
})

/**
 * bubble_sort_dsc
 *
 * sort container items in descending order
 *
 * @self:       the instance
 * @prefix      the prefix of _first(), _next() and _move_before() methods
 * @cmp:        the type safe cmp
 * @type:       the optional structure type of container
 * @member:     the optional name of the node within the struct.
 *
 * container set requires defined _first(), _next(), _move_before() methods
 * 
 */

#define bubble_sort_dsc(self,prefix, ...) \
	va_dispatch(bubble_sort_dsc,__VA_ARGS__)(self,prefix,__VA_ARGS__)
#define bubble_sort_dsc1(self,prefix,cmp) \
({ \
	for (prefix##_node *z, *y, *x = prefix##_first(self); x; ) { \
		for (z = y = x; (y = prefix##_next(self, y)); )   \
			if (cmp(y, z) > 0) z = y; \
		if (x == z) \
			x = prefix##_next(self, x); \
		else \
			prefix##_move_before(z, x); \
	} \
})
#define bubble_sort_dsc3(self,prefix,cmp,type,member) \
({ \
	for (prefix##_node *z, *y, *x = prefix##_first(self); x; ) { \
		for (z = y = x; (y = prefix##_next(self, y)); )   \
			if (container_cmp(cmp, y, z, type, member) > 0) z = y;\
		if (x == z) \
			x = prefix##_next(self, x); \
		else \
			prefix##_move_before(z, x); \
	} \
})

/**
 * merge_sort
 *
 * sort container items in ascending order
 *
 * @self:       the container
 * @prefix      the prefix of _first(), _next() and _move_before() methods
 * @cmp:        the type safe cmp
 * @type:       the optional structure type
 * @member:     the optional name of the node within the struct.
 *
 * Merge sort is a divide and conquer algorithm that was invented by 
 * John von Neumann in 1945.
 *
 * Merge sort is often the best choice for sorting a linked list
 *
 */

#define merge_sort(self,prefix, ...) \
	va_dispatch(merge_sort_asc,__VA_ARGS__)(self,prefix,__VA_ARGS__)

/**
 * merge_sort_asc
 *
 * sort container items in ascending order
 *
 * @self:       the container
 * @prefix      the prefix of _first(), _next() and _move_before() methods
 * @cmp:        the type safe cmp
 * @type:       the optional structure type
 * @member:     the optional name of the node within the struct.
 */

#define merge_sort_asc(self,prefix, ...) \
	va_dispatch(merge_sort_asc,__VA_ARGS__)(self,prefix,__VA_ARGS__)

#define __merge_sort_range_asc(ctx,pos,to,...) \
	va_dispatch(__merge_sort_range_asc,__VA_ARGS__)(ctx,pos,to,__VA_ARGS__)
#define __merge_sort_range_asc1(ctx,pos,to,cmp) \
({ \
 	struct node *n = pos; \
	for (int i = (ctx)->a; i < to; ++i) { \
		n = slist_merge_sorted_asc((ctx)->p[i], n, cmp); \
		(ctx)->p[i] = NULL; \
	} n; \
})
#define __merge_sort_range_asc3(ctx,pos,to,cmp,type,member) \
({ \
 	struct node *n = pos; \
	for (int i = (ctx)->a; i < to; ++i) { \
		n = slist_merge_sorted_asc((ctx)->p[i], n, cmp, type,member); \
		(ctx)->p[i] = NULL; \
	} n; \
})

#define __merge_sort_insert_asc(ctx,node,pos, ...) \
	va_dispatch(__merge_sort_insert_asc,__VA_ARGS__)(ctx,node,pos,__VA_ARGS__)
#define __merge_sort_insert_asc1(ctx,node,pos,cmp) \
({ \
	int i, index = pos; \
	if (pos > (ctx)->b) { \
		if (pos > (1 << SORT_MERGE_BOTTOM_UP_SHIFT)) \
			index = (1 << SORT_MERGE_BOTTOM_UP_SHIFT); \
		node = slist_merge_sorted_asc(__merge_sort_range_asc((ctx), NULL, \
		                         (ctx)->b, cmp), node, cmp); \
		for (i = (ctx)->b; i < index; i++) (ctx)->p[i] = NULL; \
	} else { \
		if (pos) \
			node = slist_merge_sorted_asc(__merge_sort_range_asc((ctx), \
			                         NULL, pos, cmp), node, cmp); \
		for (i = pos; i < (ctx)->b && (ctx)->p[i]; i++) { \
			node = slist_merge_sorted_asc((ctx)->p[i], node, cmp); \
			(ctx)->p[i] = NULL; \
		} \
	} \
	if (i == (1 << SORT_MERGE_BOTTOM_UP_SHIFT)) --i; \
	if (i >= (ctx)->b) (ctx)->b = i + 1; \
	(ctx)->a = i; (ctx)->p[i] = node; \
})

#define __merge_sort_insert_asc3(ctx, node, pos, cmp, type, member) \
({ \
	int i, index = pos; \
	if (pos > (ctx)->b) { \
		if (pos > (1 << SORT_MERGE_BOTTOM_UP_SHIFT)) \
			index = (1 << SORT_MERGE_BOTTOM_UP_SHIFT); \
		node = slist_merge_sorted_asc(__merge_sort_range_asc((ctx), NULL, \
		      (ctx)->b, cmp, type, member), node, cmp, type, member); \
		for (i = (ctx)->b; i < index; i++) (ctx)->p[i] = NULL; \
	} else { \
		if (pos) \
			node = slist_merge_sorted_asc(__merge_sort_range_asc((ctx), \
			NULL, pos, cmp, type, member), node, cmp, type, member); \
		for (i = pos; i < (ctx)->b && (ctx)->p[i]; i++) { \
			node = slist_merge_sorted_asc((ctx)->p[i], node, cmp, type, member); \
			(ctx)->p[i] = NULL; \
		} \
	} \
	if (i == (1 << SORT_MERGE_BOTTOM_UP_SHIFT)) --i; \
	if (i >= (ctx)->b) (ctx)->b = i + 1; \
	(ctx)->a = i; (ctx)->p[i] = node; \
})

#define merge_sort_asc1(self, prefix, cmp) \
({ \
	if (!list_empty(self) && !list_singular(self)) { \
	struct { unsigned a, b; \
	struct node *p[(1 << SORT_MERGE_BOTTOM_UP_SHIFT)]; } ctx = {0,0}; \
	struct node *x, *y, *z = prefix##_disable_prev(self); \
	for (y = z->next->next; z && (x = z->next) && ({y = x->next;1;});) { \
		if (cmp(x, z) < 0) { x->next = z; x = z; z = z->next; } \
		x->next = NULL; \
		__merge_sort_insert_asc(&ctx, z, 0, cmp);\
		z = y; \
	} \
	z = __merge_sort_range_asc(&ctx, z, ctx.b, cmp); \
	prefix##_enable_prev(self, z); \
	} \
})

#define merge_sort_asc3(self,prefix,cmp,type,member) \
({ \
	if (!list_empty(self) && !list_singular(self)) { \
	struct { unsigned a, b; \
	struct node *p[(1 << SORT_MERGE_BOTTOM_UP_SHIFT)]; } ctx = {0,0}; \
	struct node *x, *y, *z = prefix##_disable_prev(self); \
	for (y = z->next->next; z && (x = z->next) && ({y = x->next;1;});) { \
		if (container_cmp(cmp, x, z, type, member) < 0) \
			{ x->next = z; x = z; z = z->next; } \
		x->next = NULL; \
		__merge_sort_insert_asc(&ctx, z, 0, cmp, type, member);\
		z = y; \
	} \
	z = __merge_sort_range_asc(&ctx, z, ctx.b, cmp, type, member); \
	prefix##_enable_prev(self, z); \
	} \
})


/**
 * invers_asc - inversion count in ascending order
 *
 * If set is already sorted then inversion count is 0. If set is sorted in 
 * reverse order that inversion count is the maximum. 
 *
 * @self:       the instance
 * @prefix      the prefix of _first(), _next() and _move_before() methods
 * @cmp:        the type safe cmp
 * @type:       the optional structure type of container
 * @member:     the optional name of the node within the struct.
 *
 * container set requires _first(), _next()
 *
 */

#define invers_asc(self,prefix, ...) \
	va_dispatch(invers_asc,__VA_ARGS__)(self,prefix,__VA_ARGS__)
#define invers_asc1(self,prefix,cmp) \
({ \
 	prefix##_node *y, *x; \
 	unsigned inv = 0; \
	for (x = prefix##_first(self); x && x->next; x = prefix##_next(self, x)) \
		for (y = x; (y = prefix##_next(self, y)); ) \
			if (cmp(x, y) > 0) inv++; \
	inv; \
})
#define invers_asc3(self,prefix,cmp,type,member) \
({ \
  	prefix##_node *y, *x; \
 	unsigned inv = 0; \
	for (x = prefix##_first(self);x && x->next;x = prefix##_next(self, x))  \
		for (y = x; (y = prefix##_next(self, y)); )  \
			if (container_cmp(cmp, x, y, type, member) > 0) inv++;\
	inv; \
})

/**
 * invers_dsc - inversion count in descending order
 *
 * If set is already sorted then inversion count is 0. If set is sorted in 
 * reverse order that inversion count is the maximum. 
 *
 * @self:       the instance
 * @prefix      the prefix of _first(), _next() and _move_before() methods
 * @cmp:        the type safe cmp
 * @type:       the optional structure type of container
 * @member:     the optional name of the node within the struct.
 *
 * container set requires _first(), _next()
 *
 */

#define invers_dsc(self,prefix, ...) \
	va_dispatch(invers_dsc,__VA_ARGS__)(self,prefix,__VA_ARGS__)
#define invers_dsc1(self,prefix,cmp) \
({ \
 	prefix##_node *y, *x; \
 	unsigned inv = 0; \
	for (x = prefix##_first(self); x; x = prefix##_next(self, x)); ) \
		for (y = x; (y = prefix##_next(self, y)); ) \
			if (cmp(x, y) > 0) inv++; \
	inv; \
})
#define invers_dsc3(self,prefix,cmp,type,member) \
({ \
  	prefix##_node *y, *x; \
 	unsigned inv = 0; \
	for (x = prefix##_first(self); x; x = prefix##_next(self, x)); ) \
		for (y = x; (y = prefix##_next(self, y)); ) \
			if (container_cmp(cmp, x, y, type, member) > 0) inv++;\
	inv; \
})

struct list;
struct node;
void
merge_sort_asc_recursive(struct list *, int (*fb)(struct node *, struct node *));

#endif/*__CCE_GENERIC_SORT_H__*/
