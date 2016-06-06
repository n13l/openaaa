/*
 * Generic Single linked, Double linked and Circular doubly-linked list
 *
 * The MIT License (MIT)         Copyright (c) 2015 Daniel Kubec <niel@rtfm.cz>
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

#ifndef __MEM_LIST_H__
#define __MEM_LIST_H__

#include <sys/compiler.h>
#include <mem/alloc.h>

struct node {
	struct node *next, *prev;
};

struct snode {
	struct cnode *next;
};

struct hnode {
	struct hnode *next, **prev;
};

struct list {
	struct node head;
};

struct slist {
	struct snode *head;
};

struct dlist {
	struct dlist *next, *prev;
};

struct hlist {
	struct hnode *first;
};


static inline void
slist_remove(struct snode *node, struct snode *prev)
{
	if (prev)
		prev->next = node->next;
}

#define slist_for_each_safe(item, member, it) \
	for (; item && ({it = (__typeof__(item))item->member.next; 1;} ); item = it)

static inline void 
list_init(struct list *l)
{
	struct node *head = &l->head;
	head->next = head->prev = head;
}

static inline void *
list_head(struct list *l)
{
	return (l->head.next != &l->head) ? l->head.next : NULL;
}

static inline void *
list_tail(struct list *l)
{
	return (l->head.prev != &l->head) ? l->head.prev : NULL;
}

static inline void *
list_next(struct list *l, struct node *n)
{
	return (n->next != &l->head) ? (void *) n->next : NULL;
}

static inline void *
list_prev(struct list *l, struct node *n)
{
	return (n->prev != &l->head) ? (void *) n->prev : NULL;
}

static inline int
list_empty(struct list *l)
{
	return (l->head.next == &l->head);
}

static inline void
list_insert_after(struct node *what, struct node *after)
{
	struct node *before = after->next;
	what->next = before;
	what->prev = after;
	before->prev = what;
	after->next = what;
}

static inline void
list_insert_before(struct node *what, struct node *before)
{
	struct node *after = before->prev;
	what->next = before;
	what->prev = after;
	before->prev = what;
	after->next = what;
}

static inline void
list_add_head(struct list *l, struct node *n)
{
	list_insert_after(n, &l->head);
}

static inline void
list_add_tail(struct list *l, struct node *n)
{
	list_insert_before(n, &l->head);
}

static inline void
list_remove(struct node *n)
{
	struct node *before = n->prev;
	struct node *after = n->next;
	before->next = after;
	after->prev = before;
}

static inline void *
list_remove_head(struct list *l)
{
	struct node *n = (struct node *)list_head(l);
	if (n)
		list_remove(n);
	return n;
}

static inline void 
list_insert_list_after(struct list *what, struct node *after)
{
	if (list_empty(what))
		return;

	struct node *w = &what->head;
	w->prev->next = after->next;
	after->next->prev = w->prev;
	w->next->prev = after;
	after->next = w->next;
	list_init(what);
}

static inline void
list_move(struct list *to, struct list *from)
{
	list_init(to);
	list_insert_list_after(from, &to->head);
	list_init(from);
}

#define list_walk(n, list) \
	for (n = (void*)(list).head.next;\
		(struct node*)(n) != &(list).head;\
		n = (void*)((struct node*)(n))->next)

#define list_walk_delsafe(n, list, tmp) \
	for (n = (void*)(list).head.next;\
		tmp = (void*)((struct node*)(n))->next, \
		(struct node*)(n) != &(list).head;\
		n = (void*)tmp)

#define list_for_each(type, n, list) \
	for (type n = (type)(list).head.next;\
		(struct node*)(n) != &(list).head;\
		n = (type)((struct node*)(n))->next)

#define list_for_each_delsafe(type, n, list, tmp) \
	for (type n = (void*)(list).head.next; \
		tmp = (void*)((struct node*)(n))->next, \
		(struct node*)(n) != &(list).head;\
		n = (void*)tmp)


#define list_head_init(name) { &(name), &(name) }
#define dlist_head(name) struct dlist name = list_head_init(name)

static inline void
init_list_head(struct dlist *list)
{
	list->next = list;
	list->prev = list;
}

#ifndef CONFIG_DEBUG_LIST
static inline void
__dlist_add(struct dlist *h, struct dlist *p, struct dlist *n)
{
	n->prev = h;
	h->next = n;
	h->prev = p;
	p->next = h;
}
#else
extern void 
__dlist_add(struct dlist *h, struct dlist *p, struct dlist *n);
#endif

static inline void
dlist_add(struct dlist *n, struct dlist *head)
{
	__dlist_add(n, head, head->next);
}

static inline void
dlist_add_tail(struct dlist *n, struct dlist *head)
{
	__dlist_add(n, head->prev, head);
}

static inline void
__dlist_del(struct dlist *prev, struct dlist *next)
{
	next->prev = prev;
	prev->next = next;
}

static inline void
__dlist_del_entry(struct dlist *entry)
{
	__dlist_del(entry->prev, entry->next);
}

#ifndef CONFIG_DEBUG_LIST

static inline void
dlist_del(struct dlist *entry)
{
	__dlist_del(entry->prev, entry->next);
}
#else
void
debug_dlist_del(struct dlist *entry);
#define dlist_del debug_dlist_del
#endif

static inline void
dlist_replace(struct dlist *old, struct dlist *n)
{
	n->next = old->next;
	n->next->prev = n;
	n->prev = old->prev;
	n->prev->next = n;
}

static inline void
dlist_replace_init(struct dlist *old, struct dlist *n)
{
	dlist_replace(old, n);
	init_list_head(old);
}

static inline void
dlist_del_init(struct dlist *entry)
{
	__dlist_del_entry(entry);
	init_list_head(entry);
}

static inline void
dlist_move(struct dlist *list, struct dlist *head)
{
	__dlist_del_entry(list);
	dlist_add(list, head);
}

static inline void
dlist_move_tail(struct dlist *list, struct dlist *head)
{
	__dlist_del_entry(list);
	dlist_add_tail(list, head);
}

static inline int
dlist_is_last(const struct dlist *list, const struct dlist *head)
{
	return list->next == head;
}

static inline int
dlist_empty(const struct dlist *head)
{
	return head->next == head;
}

static inline int
dlist_empty_careful(const struct dlist *head)
{
	struct dlist *next = head->next;
	return (next == head) && (next == head->prev);
}

static inline void
dlist_rotate_left(struct dlist *head)
{
	struct dlist *first;

	if (!dlist_empty(head)) {
		first = head->next;
		dlist_move_tail(first, head);
	}
}

static inline int
dlist_is_singular(const struct dlist *head)
{
	return !dlist_empty(head) && (head->next == head->prev);
}

static inline void
__dlist_cut_position(struct dlist *list, struct dlist *head,
                     struct dlist *entry)
{
	struct dlist *new_first = entry->next;
	list->next = head->next;
	list->next->prev = list;
	list->prev = entry;
	entry->next = list;
	head->next = new_first;
	new_first->prev = head;
}

static inline void
dlist_cut_position(struct dlist *list, struct dlist *head,
                   struct dlist *entry)
{
	if (dlist_empty(head))
		return;
	if (dlist_is_singular(head) &&
		(head->next != entry && head != entry))
		return;
	if (entry == head)
		init_list_head(list);
	else
		__dlist_cut_position(list, head, entry);
}

static inline void
__dlist_splice(const struct dlist *list, struct dlist *prev,
               struct dlist *next)
{
	struct dlist *first = list->next;
	struct dlist *last = list->prev;

	first->prev = prev;
	prev->next = first;

	last->next = next;
	next->prev = last;
}

static inline void
dlist_splice(const struct dlist *list, struct dlist *head)
{
	if (!dlist_empty(list))
		__dlist_splice(list, head, head->next);
}

static inline void
dlist_splice_tail(struct dlist *list, struct dlist *head)
{
	if (!dlist_empty(list))
		__dlist_splice(list, head->prev, head);
}

static inline void
list_splice_init(struct dlist *list, struct dlist *head)
{
	if (!dlist_empty(list)) {
		__dlist_splice(list, head, head->next);
		init_list_head(list);
	}
}

static inline void
dlist_splice_tail_init(struct dlist *list, struct dlist *head)
{
	if (!dlist_empty(list)) {
		__dlist_splice(list, head->prev, head);
		init_list_head(list);
	}
}

#define dlist_entry(ptr, type, member) \
	__container_of(ptr, type, member)

#define dlist_first_entry(ptr, type, member) \
	list_entry((ptr)->next, type, member)

#define dlist_last_entry(ptr, type, member) \
	list_entry((ptr)->prev, type, member)

#define dlist_first_entry_or_null(ptr, type, member) \
	(!dlist_empty(ptr) ? dlist_first_entry(ptr, type, member) : NULL)

#define dlist_next_entry(pos, member) \
	dlist_entry((pos)->member.next, typeof(*(pos)), member)

#define dlist_prev_entry(pos, member) \
	dlist_entry((pos)->member.prev, typeof(*(pos)), member)

#define dlist_for_each(pos, head) \
	for (pos = (head)->next; pos != (head); pos = pos->next)

#define dlist_for_each_prev(pos, head) \
	for (pos = (head)->prev; pos != (head); pos = pos->prev)

#define dlist_for_each_safe(pos, n, head) \
	for (pos = (head)->next, n = pos->next; pos != (head); \
		pos = n, n = pos->next)

#define dlist_for_each_prev_safe(pos, n, head) \
	for (pos = (head)->prev, n = pos->prev; \
	     pos != (head); \
	     pos = n, n = pos->prev)

#define dlist_for_each_entry(pos, head, member)				\
	for (pos = dlist_first_entry(head, typeof(*pos), member);	\
	     &pos->member != (head);					\
	     pos = dlist_next_entry(pos, member))

#define dlist_for_each_entry_reverse(pos, head, member)			\
	for (pos = dlist_last_entry(head, typeof(*pos), member);	\
	     &pos->member != (head); 					\
	     pos = dlist_prev_entry(pos, member))

#define dlist_prepare_entry(pos, head, member) \
	((pos) ? : dlist_entry(head, typeof(*pos), member))

#define dlist_for_each_entry_continue(pos, head, member) 		\
	for (pos = list_next_entry(pos, member);			\
	     &pos->member != (head);					\
	     pos = list_next_entry(pos, member))

#define dlist_for_each_entry_continue_reverse(pos, head, member)	\
	for (pos = dlist_prev_entry(pos, member);			\
	     &pos->member != (head);					\
	     pos = dlist_prev_entry(pos, member))

#define dlist_for_each_entry_from(pos, head, member) 			\
	for (; &pos->member != (head);					\
	     pos = dlist_next_entry(pos, member))

#define dlist_for_each_entry_safe(pos, n, head, member)			\
	for (pos = dlist_first_entry(head, typeof(*pos), member),	\
		n = dlist_next_entry(pos, member);			\
	     &pos->member != (head); 					\
	     pos = n, n = dlist_next_entry(n, member))

#define dlist_for_each_entry_safe_continue(pos, n, head, member) 	\
	for (pos = dlist_next_entry(pos, member), 			\
		n = dlist_next_entry(pos, member);			\
	     &pos->member != (head);					\
	     pos = n, n = dlist_next_entry(n, member))

#define dlist_for_each_entry_safe_from(pos, n, head, member) 		\
	for (n = dlist_next_entry(pos, member);				\
	     &pos->member != (head);					\
	     pos = n, n = dlist_next_entry(n, member))

#define dlist_for_each_entry_safe_reverse(pos, n, head, member)		\
	for (pos = dlist_last_entry(head, typeof(*pos), member),	\
		n = dlist_prev_entry(pos, member);			\
	     &pos->member != (head); 					\
	     pos = n, n = dlist_prev_entry(n, member))

#define dlist_safe_reset_next(pos, n, member)				\
	n = dlist_next_entry(pos, member)

#define hlist_head_init { .first = NULL }
#define hlist_head(name) struct hlist name = {  .first = NULL }
#define init_hlist_head(ptr) ((ptr)->first = NULL)

static inline void
init_hlist_node(struct hnode *h)
{
	h->next = NULL;
	h->prev = NULL;
}

static inline int
hlist_unhashed(const struct hnode *h)
{
	return !h->prev;
}

static inline int
hlist_empty(const struct hlist *h)
{
	return !h->first;
}

static inline void
__hlist_del(struct hnode *n)
{
	struct hnode *next = n->next;
	struct hnode **prev = n->prev;
	*prev = next;
	if (next)
		next->prev = prev;
}

static inline void
hlist_del(struct hnode *n)
{
	__hlist_del(n);
	n->next = (struct hnode *)ADDR_POISON1;
	n->prev = (struct hnode **)ADDR_POISON2;
}

static inline void
hlist_del_init(struct hnode *n)
{
	if (!hlist_unhashed(n)) {
		__hlist_del(n);
		init_hlist_node(n);
	}
}

static inline void
hlist_add_head(struct hnode *n, struct hlist *h)
{
	struct hnode *first = h->first;
	n->next = first;
	if (first)
		first->prev = &n->next;
	h->first = n;
	n->prev = &h->first;
}

static inline void
hlist_add_before(struct hnode *n, struct hnode *next)
{
	n->prev = next->prev;
	n->next = next;
	next->prev = &n->next;
	*(n->prev) = n;
}

static inline void
hlist_add_after(struct hnode *n, struct hnode *next)
{
	next->next = n->next;
	n->next = next;
	next->prev = &n->next;

	if(next->next)
		next->next->prev  = &next->next;
}

static inline void
hlist_add_fake(struct hnode *n)
{
	n->prev = &n->next;
}

static inline void
hlist_move_list(struct hlist *old, struct hlist *n)
{
	n->first = old->first;
	if (n->first)
		n->first->prev = &n->first;
	old->first = NULL;
}

#define hlist_for_each(node, head) \
	for (node = (head)->first; node ; node = item->next)

#define hlist_for_each_safe(node, n, head) \
	for (node = (head)->first; pos && ({node = pos->next; 1;}); node = n)

#define hlist_for_each_entry(node, head, member)				\
	for (node = __container_of_safe((head)->first,typeof(*(node)), member);\
	     node;							\
	     node = __container_of_safe((node)->member.next,typeof(*(node)), member))

#define hlist_for_each_entry_continue(pos, member)			\
	for (pos = __container_of_safe((pos)->member.next,typeof(*(pos)), member);\
	     pos;							\
	     pos = __container_of_safe((pos)->member.next,typeof(*(pos)), member))

#define hlist_for_each_entry_from(node, member)				\
	for (; node; node = __container_of_safe((node)->member.next,typeof(*(node)), member))

#define hlist_for_each_entry_safe(node, n, head, member) 		\
	for (node = __container_of_safe((head)->first, typeof(*node), member);\
	     node && ({ n = node->member.next; 1; });			\
	     node = __container_of_safe(n, typeof(*node), member))

#endif
