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
#define DECLARE_NODE(name)   struct node name = NODE_INIT
#define DEFINE_LIST(name)    struct list name
#define DECLARE_ITEM(type1, node, ...) \
({ \
	type1 __o = (type1) { .node = NODE_INIT, ## __VA_ARGS__ }; \
	& __o.node; \
})

#define LIST_ITEM(item, node) &(item.node)
#define NODE_INIT            { .next = NULL, .prev = NULL } 
#define INIT_LIST(name)      {{(struct node *)&(name), (struct node *)&(name)}}

#define NODE_HEAD(list) \
	(list).head.next
#define NODE_HEAD_DELSAFE(list, it) \
	({ it = (list).head.next; NULL; })
#define NODE_ITER(list, it) \
	((it) != &(list).head)
#define NODE_HEAD_TYPE(list, type, member) \
	__container_of(NODE_HEAD(list),type,member)
#define NODE_NEXT_TYPE(it, type, member) \
	__container_of((it)->member.next,type,member)
#define NODE_ITER_TYPE(list, it, member) \
	(&(it->member) != &(list).head)
#define NODE_ITER_TYPE_DELSAFE(list, it, it_next, type, member) \
	NODE_ITER_TYPE(list, it, member) && \
	({(it_next) = NODE_NEXT_TYPE(it,type,member);1;}) \
	
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
	if (list_empty(list))
		return 0;

	for (struct node *n = list->head.next; n != &list->head; n = n->next)
		size++;
	return size;
}

/**
 * list_walk  - iterate over list with declared iterator
 *
 * @list:       the your list.
 * @it:	        the type safe iterator
 * @member:     the optional name of the node within the struct.
 */

#define list_walk(list, ...) \
	va_dispatch(list_walk,__VA_ARGS__)(list,__VA_ARGS__)
#define list_walk1(list, it) \
	for ((it) = NODE_HEAD(list); NODE_ITER(list,it); (it) = (it)->next)
#define list_walk2(list, it, member) \
	for ((it) = NODE_HEAD_TYPE(list, typeof(*it), member); \
	            NODE_ITER_TYPE(list, it, member); \
	     (it) = NODE_NEXT_TYPE(it, typeof(*it), member))

/**
 * list_walk_next - iterate over list with existing iterator
 *
 * @list:       the your list.
 * @it:	        the type safe iterator
 * @member:     the optional name of the node within the struct.
 */

#define list_walk_next(list, ...) \
	va_dispatch(list_walk_next,__VA_ARGS__)(list,__VA_ARGS__)
#define list_walk_next1(list, it) \
	for ((it) = (it)->next; NODE_ITER(list,it); (it) = (it)->next)
#define list_walk_next2(list, it, member) \
	for ((it) = NODE_NEXT_TYPE(it, typeof(*it), member); \
	            NODE_ITER_TYPE(list, it, member); \
	     (it) = NODE_NEXT_TYPE(it, typeof(*it), member))

/**
 * list_walk_delsafe  - iterate over list with declared iterator
 *
 * @list:       the your list.
 * @it:	        the type safe iterator
 * @member:	the optional name of the node within the struct.
 */

#define list_walk_delsafe(list, ...) \
	va_dispatch(list_walk_delsafe,__VA_ARGS__)(list,__VA_ARGS__)
#define list_walk_delsafe1(list, it) \
	for (typeof(*it) *(it_next) = NODE_HEAD_DELSAFE(list, it); \
	     ((it) != &list.head) && ({(it_next) = (it)->next;1;}); \
	     (it) = it_next)

/**
 * list_for_each - iterate over list 
 *
 * @list:       the your list.
 * @it:	        the type safe iterator
 * @type:       the optional structure type
 * @member:	the optional name of the node within the struct.
 */

#define list_for_each(list, ...) \
	va_dispatch(list_for_each,__VA_ARGS__)(list,__VA_ARGS__)
#define list_for_each1(list, it) \
	for (struct node *(it) = NODE_HEAD(list); \
	    (it) != &(list).head; (it) = (it)->next)
#define list_for_each3(list, it, type, member) \
	for (type *(it) = NODE_HEAD_TYPE(list, type, member); \
	     &(it->member) != &(list).head; \
	     (it) = NODE_NEXT_TYPE(it, type, member))

/**
 * list_for_each_delsafe - iterate over list with safety against removal
 *
 * @list:       the your list.
 * @it:	        the type safe iterator 
 * @type:       the optional structure type
 * @member:	the optional name of the node within the struct.
 */

#define list_for_each_delsafe(list, ...) \
	va_dispatch(list_for_each_delsafe,__VA_ARGS__)(list,__VA_ARGS__)
#define list_for_each_delsafe1(list, it) \
	for (struct node *__it, *it = (list).head.next; \
	     (__it) = it->next, (it) != &(list).head; (it) = __it)
#define list_for_each_delsafe3(list, it, type, member) \
	for (type *__it, *it = NODE_HEAD_TYPE(list, type, member); \
	     NODE_ITER_TYPE_DELSAFE(list, it, __it, type, member);(it) = __it)

/**
 * list_sort  - sort list 
 *
 * @list:       the your list.
 * @fn:	        the type safe comparator
 * @type:       the optional structure type
 * @member:	the optional name of the node within the struct.
 */

#define list_sort(list, ...) \
	va_dispatch(list_sort_asc,__VA_ARGS__)(list,__VA_ARGS__)

/**
 * list_sort_asc  - sort list 
 *
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
#define list_sort_asc3(list, __cmp_fn, type, member) \
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
 * list_sort_dsc  - sort list 
 *
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
#define list_sort_dsc3(list, cmp_fn, __type, member) \
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
#define list_ddup1(list, typecmp) \
{ \
	struct node *ddup1_prev = NULL; \
	list_for_each_delsafe(*(list), it) { \
		if (ddup1_prev && !typecmp(ddup1_prev, it)) \
			list_del(it); else ddup1_prev = it; \
	} \
}
#define list_ddup3(list, typecmp, type, member) \
{ \
	type *ddup3_prev = NULL; \
	list_for_each_delsafe(*(list), it, type, member) { \
		if (ddup3_prev && !typecmp(ddup3_prev, it)) \
			list_del(&(it->member)); else ddup3_prev = it; \
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
	for (; item; item = it)

#define slist_for_each_delsafe(item, member, it) \
	for (; item && ({it=(typeof(item))item->member.next;1;}); item = it)

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
	if (!hnode->prev)
		return;
	
	struct hnode *next  = hnode->next;
	struct hnode **prev = hnode->prev;
	*prev = next;
	if (next)
		next->prev = prev;

	hnode_init(hnode);
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

#define HNODE_HEAD(list) ({ list->head; })
#define HNODE_NEXT(node) ({ node->next; })
#define HNODE_ITER_DELSAFE(it, it_next) \
	((it)&&({(it_next)=(it)->next;1;}))
#define HNODE_HEAD_DELSAFE(list, it) \
	({ it = (list).head; NULL; })

#define HNODE_HEAD_TYPE_DELSAFE(list, it, member) \
	({it = __container_of_safe((list)->head, typeof(*it), member); NULL; })
#define HNODE_NEXT_TYPE(it_next, type, member) \
	__container_of_safe(it_next, type, member)
#define HNODE_ITER_TYPE_DELSAFE(it, it_next, type, member) \
	((it)&&({(it_next)=(it)->member.next;1;}))

/**
 * hlist_walk - iterate over list with declared iterator
 *
 * @list:       the your list.
 * @it:	        iterator
 * @member:	the optional name of the node within the struct.
 */

#define hlist_walk(list, ...) \
	va_dispatch(hlist_walk,__VA_ARGS__)(list,__VA_ARGS__)
#define hlist_walk1(list, it) \
	for ((it)=HNODE_HEAD((list));it;(it)=HNODE_NEXT((it)))
#define hlist_walk2(list, it, member) \
	for ((it)=HNODE_HEAD((list));it;(it)=HNODE_NEXT((it)))

/**
 * hlist_walk_delsafe - iterate over list with safety against removal
 *
 * @list:       the your list.
 * @it:	        iterator
 * @member:	the optional name of the node within the struct.
 */

#define hlist_walk_delsafe(list, ...) \
	va_dispatch(hlist_walk_delsafe,__VA_ARGS__)(list,__VA_ARGS__)
#define hlist_walk_delsafe1(list, it) \
	for (struct hnode *__it = HNODE_HEAD_DELSAFE((list,it)); \
	                          HNODE_ITER_DELSAFE(it, __it); (it)=__it)
#define hlist_walk_delsafe2(list, it, member) \
	for (struct hnode *__it = HNODE_HEAD_TYPE_DELSAFE(list,it,member); \
	                   ((it)&&({(__it)=(it)->member.next;1;})); \
	                     it = HNODE_NEXT_TYPE(__it,typeof(*it),member))

/**
 * hlist_for_each - iterate over list
 *
 * @list:       the your list.
 * @it:	        iterator
 * @type:       the optional structure type
 * @member:	the optional name of the node within the struct.
 */

#define hlist_for_each(list, ...) \
	va_dispatch(hlist_for_each,__VA_ARGS__)(list,__VA_ARGS__)
#define hlist_for_each1(list, it) \
	for (struct hnode *(it)=HNODE_HEAD((list));it;(it)=HNODE_NEXT((it)))
#define hlist_for_each2(list, it, member) \
	for (struct hnode *(it)=HNODE_HEAD((list));it;(it)=HNODE_NEXT((it)))

/**
 * hlist_for_each_delsafe - iterate over list with safety against removal
 *
 * @list:       the your list
 * @it:	        iterator
 * @type:       the optional structure type
 * @member:	the optional name of the node within the struct.
 */

#define hlist_for_each_delsafe(list, ...) \
	va_dispatch(hlist_for_each_delsafe,__VA_ARGS__)(list,__VA_ARGS__)
#define hlist_for_each_delsafe1(list, it) \
	for (struct hnode *(it) = HNODE_HEAD((list)), *__it; \
	     HNODE_ITER_DELSAFE(it, __it); (it) = __it)
#define hlist_for_each_delsafe3(list, it, type, member) \
	for (struct hnode *(it) = HNODE_HEAD((list)), *__it; \
	     HNODE_ITER_DELSAFE(it, __it); (it) = __it)

__END_DECLS

#endif/*__GENERIC_LIST_H__*/
