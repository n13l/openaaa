/* This file contains the linked list implementations for DEBUG_LIST. */

#include <sys/compiler.h>
#include <sys/cpu.h>
#include <mem/alloc.h>
#include <stdlib.h>
#include <time.h>
#include <posix/timespec.h>
#include <posix/list.h>

#define list_debug(fmt, ...) \
	debug("%s() " fmt, __func__, __VA_ARGS__)

void
__list_init(struct list *list)
{
	struct node *head = &list->head;
	head->next = head->prev = head;
	list_debug("list=%p head=%p", list, head);
}

void *
__list_head(struct list *list)
{
	list_debug("list=%p head=%p head.next=%p", 
	           list, &list->head, list->head.next);

	return (list->head.next != &list->head) ? list->head.next : NULL;
}
#
void 
__list_del(struct node *node)
{
	debug("node=%p", node);

	struct node *before = node->prev;
	struct node *after = node->next;
	before->next = after;
	after->prev = before;

	node->next = MM_ADDR_POISON1;
	node->prev = MM_ADDR_POISON2;
}

void
__hlist_del(struct hnode *hnode)
{
	debug("hnode=%p", hnode);

	struct hnode *next = hnode->next;
	struct hnode **prev = hnode->prev;
	if ((*prev = next))
		next->prev = prev;

	hnode->next = (struct hnode * )MM_ADDR_POISON1;
	hnode->prev = (struct hnode **)MM_ADDR_POISON2;
}
