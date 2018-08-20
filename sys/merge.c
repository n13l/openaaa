#include <sys/compiler.h>
#include <list.h>

#define __do_merge_sort_r_xy_not_null(x, y, fn, cb) \
({ (x) == NULL ? (y): (y) == NULL ? (x): fn((x), (y), (cb)); })

#define __do_merge_sort_r_a(x, y, fn, cb) \
({ \
	x->next = __do_merge_sort_r_xy_not_null(x->next, y, fn, cb); \
	x->next->prev = x; x->prev = NULL; x; \
})
#define __do_merge_sort_r_b(x, y, fn, cb) \
({ \
	y->next = __do_merge_sort_r_xy_not_null(x, y->next, fn, cb); \
	y->next->prev = y; y->prev = NULL; y; \
})

struct node *
__do_merge_sort_asc_r(struct node *x, struct node *y, 
                      int (*fn)(struct node *, struct node *))
{
	if (fn(x, y) < 0)
		return __do_merge_sort_r_a(x, y, __do_merge_sort_asc_r, fn);
	else
		return __do_merge_sort_r_b(x, y, __do_merge_sort_asc_r, fn);
}

struct node *
do_merge_sort_asc_r(struct node *x, int (*fn)(struct node *, struct node *))
{
	if (!x || !x->next)
		return x;

	struct node *y = snode_split(x);
	x = do_merge_sort_asc_r(x, fn);
	y = do_merge_sort_asc_r(y, fn);
	return __do_merge_sort_r_xy_not_null(x, y, __do_merge_sort_asc_r, fn);
}

void
merge_sort_asc_recursive(struct list *self, int (*fn)(struct node *, struct node *))
{
	if (list_empty(self) || list_singular(self))
		return;
	struct node *x = list_disable_prev(self);
	struct node *y = do_merge_sort_asc_r(x, fn);
	list_enable_prev(self, y);
}
