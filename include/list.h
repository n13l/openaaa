/*
 * Generic Single linked, Double linked and Circular doubly-linked list
 *
 * The MIT License (MIT)         
 *
 * Copyright (c) 2013 - 2019                        Daniel Kubec <niel@rtfm.cz>
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
 **/

#ifndef __GENERIC_LIST_H__
#define __GENERIC_LIST_H__

#include <sys/compiler.h>
#include <sys/decls.h>

__BEGIN_DECLS

#define DECLARE_LIST(name)   struct list name = INIT_LIST(name)
#define DECLARE_NODE(name)   struct node name = INIT_NODE
#define DEFINE_LIST(name)    struct list name
#define DECLARE_ITEM(type1, node, ...) \
({ \
	type1 __o = (type1) { .node = INIT_NODE, ## __VA_ARGS__ }; \
	& __o.node; \
})

#define LIST_ITEM(item, node) &(item.node)
#define INIT_NODE            { .next = NULL, .prev = NULL } 
#define INIT_LIST(name)      {{(struct node *)&(name), (struct node *)&(name)}}

struct node  { struct node  *next, *prev; };
struct snode { struct snode *next; };
struct hnode { struct hnode *next, **prev; };
struct list  { struct node   head; };
struct slist { struct snode *head; };
struct hlist { struct hnode *head; };

static inline void
node_init(struct node *node)
{
	node->next = node->prev = NULL;
}

static inline void
list_init(struct list *list)
{
	struct node *head = &list->head;
	head->next = head->prev = head;
}

static inline void *
list_head(struct list *list)
{
	return (list->head.next != &list->head) ? list->head.next: NULL;
}

static inline void *
list_first(struct list *list)
{
	return (list->head.next != &list->head) ? list->head.next: NULL;
}

static inline void *
list_tail(struct list *list)
{
	return (list->head.prev != &list->head) ? list->head.prev: NULL;
}

static inline void *
list_last(struct list *list)
{
	return (list->head.prev != &list->head) ? list->head.prev: NULL;
}

static inline void *
list_next(struct list *list, struct node *node)
{
	return (node->next != &list->head) ? (void *)node->next: NULL;
}

static inline void *
list_prev(struct list *list, struct node *node)
{
	return (node->prev != &list->head) ? (void *)node->prev: NULL;
}

static inline int
list_empty(struct list *list)
{
	return (list->head.next == &list->head);
}

static inline void
list_add_after(struct node *node, struct node *after)
{
	struct node *before = after->next;
	node->next = before;
	node->prev = after;
	before->prev = node;
	after->next = node;
}

static inline void
list_add_before(struct node *node, struct node *before)
{
	struct node *after = before->prev;
	node->next = before;
	node->prev = after;
	before->prev = node;
	after->next = node;
}

static inline void
list_add_head(struct list *list, struct node *node)
{
	list_add_after(node, &list->head);
}

static inline void
list_add_tail(struct list *list, struct node *node)
{
	list_add_before(node, &list->head);
}

static inline void
list_add(struct list *list, struct node *node)
{
	list_add_before(node, &list->head);
}

static inline void 
list_del(struct node *node)
{
	struct node *before = node->prev;
	struct node *after  = node->next;
	before->next = after;
	after->prev = before;
}

static inline unsigned int
list_size(struct list *list)
{
	unsigned int size = 0;
	for (struct node *n = list->head.next; n != &list->head; n = n->next)
		size++;

	return size;
}


#define __list_walk_first(N) (N)
#define __list_walk_next(N) (N)
#define __list_walk_first_delsafe(N) (N)
#define __list_walk_next_delsafe(N) (N)

#define list_for_first(__list) (__list).head.next
#define list_for_head(list) &(list).head
#define list_for_last(list, node) &(it->node) != &(list).head

#define list_walk(__list, __node, __it) \
	for (struct node *(__it) = (__node); (__it) != &__list.head; \
	     (__it) = (__it)->next)

#define list_walk_delsafe(list, __node, __it) \
	for (struct node *it, *(__it) = (__node); it = (__it)->next, \
	     (__it) != &list.head; (__it) = it)

/**
 * list_for_each - iterate over list 
 * @list:       the your list.
 * @it:	        the type safe iterator to use as a loop cursor.
 * @type:       the optional structure type
 * @member:	the optional name of the node within the struct.
 */

#define list_for_each(list, ...) \
	va_dispatch(list_for_each,__VA_ARGS__)(list,__VA_ARGS__)
#define list_for_each1(list, it) \
	for (struct node *(it) = (list).head.next; \
	    (it) != &(list).head; (it) = (it)->next)
#define list_for_each3(list, it, type, member) \
	for (type *(it) = __container_of(list_for_first(list), type, member); \
	     &(it->member) != &(list).head; \
	     (it) = __container_of(it->member.next, type, member))

/**
 * list_for_each_delsafe - iterate over list with safety against removal
 * @list:       the your list.
 * @it:	        the type safe iterator to use as a loop cursor.
 * @type:       the optional structure type
 * @member:	the optional name of the node within the struct.
 */

#define list_for_each_delsafe(list, ...) \
	va_dispatch(list_for_each_delsafe,__VA_ARGS__)(list,__VA_ARGS__)

#define list_for_each_delsafe1(list, n) \
	for (struct node *__it, *(n) = (list).head.next; \
		(__it) = (n)->next, (n) != &(list).head; (n) = __it)

#define list_for_each_delsafe3(list, n, type, member) \
	for (struct node *__it, *(n) = (list).head.next; \
		(__it) = (n)->next, (n) != &(list).head; (n) = __it)

#define list_for_each_item(__list, __it, __node) \
	for ((__it) = __container_of(list_for_first(__list), typeof(*__it), __node); \
	     &(__it->__node) != &(__list).head; \
	     (__it) = __container_of(__it->__node.next, typeof(*__it), __node))

/**
 * list_sort  - sort list 
 * @list:       the your list.
 * @fn:	        the type safe comparator
 * @type:       the optional structure type
 * @member:	the optional name of the node within the struct.
 */

#define list_sort(list, ...) \
	va_dispatch(list_sort_asc,__VA_ARGS__)(list,__VA_ARGS__)

/**
 * list_sort_asc  - sort list 
 * @list:       the your list.
 * @fn:	        the type safe comparator
 * @type:       the optional structure type
 * @member:	the optional name of the node within the struct.
 */

#define list_sort_asc(list, ...) \
	va_dispatch(list_sort_asc,__VA_ARGS__)(list,__VA_ARGS__)
#define list_sort_asc1(list, __cmp_fn) \
        for (struct node *z, *y, *x = list_head(list); x; ) { \
                for (z = y = x; (y = list_next(list, y)); )   \
                        if (__cmp_fn(y, z) < 0) z = y; \
                if (x == z) \
			x = list_next(list, x); \
		else { \
			list_del(z); list_add_before(z, x); \
		} \
        }

/**
 * list_sort_dsc  - sort list 
 * @list:       the your list.
 * @fn:	        the type safe comparator
 * @type:       the optional structure type
 * @member:	the optional name of the node within the struct.
 */

#define list_sort_dsc(list, ...) \
	va_dispatch(list_sort_dsc,__VA_ARGS__)(list,__VA_ARGS__)
#define list_sort_dsc1(list, __cmp_fn) \
        for (struct node *z, *y, *x = list_head(list); x; ) { \
                for (z = y = x; (y = list_next(list, y)); )   \
                        if (__cmp_fn(y, z) > 0) z = y; \
                if (x == z) \
                        x = list_next(list, x); \
                else { \
                        list_del(z); list_add_before(z, x); \
                } \
        }
#define list_sort3(list, __cmp_fn, __type, __node) \
	list_sort_asc3(list, __cmp_fn, __type, __node)
#define list_sort_asc3(list, __cmp_fn, __type, __node) \
        for (struct node *z, *y, *x = list_head(list); x; ) { \
                for (z = y = x; (y = list_next(list, y)); )   \
                        if (__cmp_fn(__container_of(y, __type, __node), \
			             __container_of(z, __type, __node)) < 0) \
				z = y; \
                if (x == z) \
                        x = list_next(list, x); \
                else { \
                        list_del(z); list_add_before(z, x); \
                } \
        }
#define list_sort_dsc3(list, cmp_fn, __type, __node) \
        for (struct node *z, *y, *x = list_head(list); x; ) { \
                for (z = y = x; (y = list_next(list, y)); )   \
                        if (cmp_fn(__container_of(y, __type, __node), \
			           __container_of(z, __type, __node)) > 0) \
				z = y; \
                if (x == z) \
                        x = list_next(list, x); \
                else { \
                        list_del(z); list_add_before(z, x); \
                } \
        }

/**
 * list_ddup  - deduplicate list
 * @list:       the your list.
 * @fn:	        the type safe comparator
 * @type:       the optional structure type
 * @member:	the optional name of the node within the struct.
 *
 * note: require sorted list
 */

#define list_ddup(list, ...) \
	va_dispatch(list_ddup,__VA_ARGS__)(list,__VA_ARGS__)
#define list_ddup1(__list, __cmp_fn) \
{ \
	struct node *__pr = NULL; \
	list_for_each_delsafe(*(__list), __node) { \
		if (__pr && !__cmp_fn(__pr, __node)) \
			list_del(__node); \
		else \
			__pr = __node; \
	} \
}
#define list_ddup3(__list, __cmp_fn, __type, __node) \
{ \
	struct node *__pr = NULL; \
	list_for_each_delsafe(*(__list), __nd) { \
		if (__pr && !__cmp_fn(__container_of(__pr, __type, __node), \
		                      __container_of(__nd, __type, __node))) \
			list_del(__nd); \
		else \
			__pr = __nd; \
	} \
}

#define list_ddup_copy(__list, __cmp_fn, __cp_fn)

static inline void
snode_init(struct snode *snode)
{
	snode->next = NULL;
}

static inline void
slist_add(struct snode *node, struct snode *after)
{
	after->next = node;
}

static inline void
slist_del(struct snode *node, struct snode *prev)
{
	if (!prev)
		return;
	prev->next = node->next;
}

#define slist_for_each(item, member, it) \
	for (; item ; item = it)

#define slist_for_each_delsafe(item, member, it) \
	for (; item && ({it = (__typeof__(item))item->member.next; 1;} ); \
	       item = it)

#define DEFINE_HLIST(name)    struct hlist name;
#define DECLARE_HLIST(name)   struct hlist name = {  .head = NULL }
#define INIT_HLIST            { .head = NULL }
#define INIT_HLIST_PTR(ptr)   ((ptr)->head = NULL)
#define INIT_HLIST_HEAD(name) { &(name), &(name) }
#define INIT_HNODE            (struct hnode) {.next = NULL, .prev = NULL}

static inline void
hnode_init(struct hnode *hnode)
{
	hnode->next = NULL;
	hnode->prev = NULL;
}

static inline int 
hnode_unhashed(struct hnode *h)
{
	return !h->prev;
}

static inline void 
hlist_add(struct hlist *hlist, struct hnode *hnode)
{
	struct hnode *head = hlist->head;
	hnode->next = head;
	if (head)
		head->prev = &hnode->next;
	hlist->head = hnode;
	hnode->prev = &hlist->head;
}

static inline int
hlist_empty(const struct hlist *hlist)
{
	return !hlist->head;
}

static inline void 
hlist_del(struct hnode *hnode)
{
	struct hnode *next  = hnode->next;
	struct hnode **prev = hnode->prev;
	*prev = next;
	if (next)
		next->prev = prev;
}

static inline void
hlist_del_init(struct hnode *n)
{
	if (hnode_unhashed(n))
		return;
	hlist_del(n);
	hnode_init(n);
}

static inline void
hlist_add_before(struct hnode *hnode, struct hnode *next)
{
	hnode->prev = next->prev;
	hnode->next = next;
	next->prev = &hnode->next;
	*(hnode->prev) = hnode;
}

static inline void
hlist_add_after(struct hnode *hnode, struct hnode *next)
{
	next->next = hnode->next;
	hnode->next = next;
	next->prev = &hnode->next;

	if(next->next)
		next->next->prev  = &next->next;
}

#define hlist_for_first(___list) ({ ___list->head; })
#define hlist_for_next(___node)  ({ ___node->next; })

#define hlist_for_each(__list, __node) \
	for (struct hnode * __node = hlist_for_first((__list)); __node; \
	     __node = hlist_for_next(__node))

#define hlist_for_each_delsafe(__list, __node) \
	for (struct hnode *(__node) = hlist_for_first((__list)), *__it; \
	     (__node) && ({__it = (__node)->next;1;}); \
	     (__node) = __it)

#define hlist_for_each_item_delsafe(item, n, list, member)                 \
	for (item = __container_of_safe((list)->head, typeof(*item), member);\
	     item && ({ n = item->member.next; 1; });                     \
	     item = __container_of_safe(n, typeof(*item), member))

__END_DECLS

#endif/*__GENERIC_LIST_H__*/
