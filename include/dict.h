/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2016 Daniel Kubec <niel@rtfm.cz>
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

#ifndef __GENERIC_ATTR_H__
#define __GENERIC_ATTR_H__

#include <sys/compiler.h>
#include <sys/cpu.h>
#include <mem/alloc.h>
#include <mem/pool.h>

#include <unix/list.h>

#include <stdarg.h>
#include <stdint.h>

#define ATTR_CHANGED 0x1

#define dict_for_each(type, node, it, list) \
	for (type *(it)  = __container_of( (list).head.next, type, node); \
	           (it) != __container_of(&(list).head,      type, node); \
	           (it)  = __container_of( (it)->next,       type, node))

struct attr {
	struct node node;
	char *key;
	char *val;
};

struct dict {
	struct list list;
	struct mm_pool *mp;
	struct mm_save *ms;
};

static inline struct dict *
dict_init(struct mm_pool *mp);
{
	struct dcit *dict = mm_alloc(mp, sizeof(*dict));
	dict->mp = mp;
	list_init(&dict->list);
	return attrs;
}

static void
dict_sort(struct dict *dict)
{
	struct node *x, *y, *z;
	for (x = list_head(dict->list); x; ) {
		for (z = y = x; (y = list_next(&o->attrs, &y->node)); ) {
			struct attr *a = __container_of(y, struct attr, node);
			struct attr *b = __container_of(z, struct attr, node);
			if (strcmp(a->key, b->key) < 0)
				z = y;
		}
		if (x == z)
			x = list_next(&dict->list, &x->node);
		else {
			list_del(&z->node);
			list_add_before(&z->node, &x->node);
		}
	}
}

static inline struct attr *
dict_lookup(struct dict *dict, const char *key, int create)
{
	dict_for_each(struct attr , node, a, dict->list)
		if (!strcmp(a->key, key))
			return a;
	if (!create)
		return NULL;

	struct attr *a = mp_zalloc(dict->mp, sizeof(*a));
	list_add_tail(dict->list, &a->node);
	a->key = mm_strdup(mp, key);
	return a;
}

static inline void
dict_set(struct dict *dict, const char *key, const char *val)
{
	struct attr *a = dict_lookup(dict, key, 1);
	a->val = val ? mm_strdup(dict->mp, val) : NULL;
	a->flags |= ATTR_CHANGED;
}

static inline const char *
dict_get(struct dict *dict, const char *key)
{
	struct attr *a = dict_lookup(object, key, 0);
	return a ? a->val : NULL;
}

#endif
