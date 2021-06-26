/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2015, 2016, 2017                  Daniel Kubec <niel@rtfm.cz>
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

#ifndef __GENERIC_DICT_H__
#define __GENERIC_DICT_H__

#include <sys/compiler.h>
#include <sys/cpu.h>
#include <mem/alloc.h>
#include <mem/pool.h>
#include <list.h>
#include <stdarg.h>
#include <stdint.h>

#define ATTR_CHANGED 0x1

#define dict_for_each(it, list) \
	for (struct attr *(it) = \
	             __container_of( (list).head.next, struct attr, node); \
	     (it) != __container_of(&(list).head,      struct attr, node); \
	     (it)  = __container_of( (it)->node.next,  struct attr, node))

struct attr {
	struct node node;
	char *key;
	char *val;
	int flags;
};

struct dict {
	struct dlist list;
	struct mm *mm;
};

static inline void
dict_init(struct dict *dict, struct mm *mm)
{
	dict->mm = mm;
	dlist_init(&dict->list);
}

static inline void
dict_sort(struct dict *dict)
{
	struct node *x, *y, *z;
	for (x = dlist_head(&dict->list); x; ) {
		for (z = y = x; (y = dlist_next(&dict->list, y)); ) {
			struct attr *a = __container_of(y, struct attr, node);
			struct attr *b = __container_of(z, struct attr, node);
			if (strcmp(a->key, b->key) < 0)
				z = y;
		}
		if (x == z)
			x = dlist_next(&dict->list, x);
		else {
			dlist_del(z);
			dlist_add_before(z, x);
		}
	}
}

static inline struct attr *
dict_lookup(struct dict *dict, const char *key, int create)
{
	dict_for_each(a, dict->list)
		if (!strcmp(a->key, key))
			return a;
	if (!create)
		return NULL;

	struct attr *a = mm_alloc(dict->mm, sizeof(*a));
	a->key = mm_strdup(dict->mm, key);
	a->node.next = NULL;
	a->node.prev = NULL;
	a->flags = 0;
	dlist_add(&dict->list, &a->node);
	return a;
}

static inline void
dict_set(struct dict *dict, const char *key, const char *val)
{
	struct attr *a = dict_lookup(dict, key, 1);
	if (!val) {
		list_del(&a->node);
		return;
	}
	a->val = mm_strdup(dict->mm, val);
	a->flags |= ATTR_CHANGED;
}

_unused static void
dict_vset(struct dict *dict, const char *key, const char *fmt, va_list args)
{
	struct attr *a = dict_lookup(dict, key, 1);
	a->flags |= ATTR_CHANGED;
	a->val = mm_vprintf(dict->mm, fmt, args);
}

_unused static void
dict_set_fmt(struct dict *dict, const char *key, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	dict_vset(dict, key, fmt, args);
	va_end(args);
}

static inline void
dict_set_nf(struct dict *dict, const char *key, const char *val)
{
	struct attr *a = dict_lookup(dict, key, 1);
	a->val = val ? mm_strdup(dict->mm, val) : NULL;
}

static inline const char *
dict_get(struct dict *dict, const char *key)
{
	struct attr *a = dict_lookup(dict, key, 0);
	return a ? a->val : NULL;
}

static inline long long int
dict_get_num(struct dict *dict, const char *key)
{
	struct attr *a = dict_lookup(dict, key, 0);
	return a ? atoll(a->val): 0;
}

static inline void
dict_dump(struct dict *dict)
{
	dict_for_each(a, dict->list)
		debug1("dump attr %s:%s", a->key, a->val);
}

int
dict_pack(struct dict *dict, char *buf, int size);

int
dict_unpack(struct dict *dict, char *buf, int len);

#endif
