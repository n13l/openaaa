/* This file contains the linked list implementations for DEBUG_LIST. */

#include <sys/compiler.h>
#include <sys/cpu.h>
#include <mem/alloc.h>
#include <mem/list.h>

void
debug_list_remove(struct node *n)
{
	struct node *before = n->prev;
	struct node *after = n->next;
	before->next = after;
	after->prev = before;
	n->next = ADDR_POISON1;
	n->prev = ADDR_POISON2;
}

void
debug_dlist_del(struct dlist *entry)
{
	entry->next->prev = entry->prev;
	entry->prev->next = entry->next;
	entry->next = (struct dlist *)ADDR_POISON1;
	entry->prev = (struct dlist *)ADDR_POISON2;
}
