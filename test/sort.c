#include <sys/compiler.h>
#include <sys/cpu.h>
#include <sys/log.h>
#include <list.h>
#include <timespec.h>
#include <stdlib.h>
#include <string.h>

DEFINE_BENCHMARK(bench);
DEFINE_LIST(list);

static struct user *db;

struct user {
	char first[32];
	char last[32];
	char gender[32];
	char race[32];
	char email[32];
	char ip[32];
	struct node n;
};

unsigned int db_size = sizeof(struct user) * 100000;
unsigned int users = 0;

static inline int user_cmp(struct user *a, struct user *b)
{
	int cmp;
	if ((cmp = strcmp(a->first, b->first)))
		return cmp;
	if ((cmp = strcmp(a->last, b->last)))
		return cmp;
	return 0;
}

_unused static inline int user_node_cmp(struct node *x, struct node *y)
{
	struct user *a = __container_of(x, struct user, n); 
	struct user *b = __container_of(y, struct user, n);
	int cmp;
	if ((cmp = strcmp(a->first, b->first)))
		return cmp;
	if ((cmp = strcmp(a->last, b->last)))
		return cmp;
	return 0;
}


_unused static inline void user_print_ln(struct user *x)
{
	printf("%s:%s\n", x->first, x->last);
}

_unused static inline void user_print(struct user *x)
{
	printf("%s:%s ", x->first, x->last);
}

static inline void
parse_line(int index, char *arg, ssize_t len) 
{
	struct user *user = db + index;
	memset(user, 0, sizeof(*user));

	for (char *p = arg; *p; p++)
		if (*p == '\n') *p = 0;

	int i = 0;
	for (char *x,*p = strtok_r(arg,",",&x);p;p = strtok_r(NULL, ",",&x)) {
		switch (i) {
		case 0: snprintf(user->race,31,"%s", p); break;
		case 1: snprintf(user->first,31,"%s",p ); break;
		case 2: snprintf(user->last,31,"%s", p); break;
		case 3: snprintf(user->email,31,"%s", p); break;
		case 4: snprintf(user->gender,31,"%s", p); break;
		}

		i++;
	}

	list_add(&list, &user->n);
}

static void
load_users_csv(void)
{
	list_init(&list);
	users = 0;
	db = db?:malloc(db_size);

	FILE *fd; char *line = NULL;
	ssize_t nr; size_t len = 0;

	if (!(fd = fopen("test/users.csv", "rb")))
		return;
        while ((nr = getline(&line, &len, fd)) != -1) {
		parse_line(users, line, len);
		users++;

		if (users >= 30000)
			break;
	}

	if (line)
		free(line);

	fclose(fd);

	BENCHMARK_INIT(bench);
}

_unused static void
test_default_sort(void)
{
	/* initialize user database because we want stable sequential access */
	load_users_csv();
	/* sort users using insert sort in ascending order */
	list_sort_asc(&list, user_cmp, struct user, n);
}

_unused static void
test_array_sort(void)
{
	/* initialize user database because we want stable sequential access */
	load_users_csv();
	/* sort users using insert-sort in ascending order */
	insert_sort_asc(&list, list, user_cmp, struct user, n);
}

_unused static void
test_insert_sort(void)
{
	/* initialize user database because we want stable sequential access */
	load_users_csv();
	/* sort users using insert-sort in ascending order */
	insert_sort_asc(&list, list, user_cmp, struct user, n);
}

_unused static void
test_select_sort(void)
{
	/* initialize user database because we want stable sequential access */
	load_users_csv();
	/* sort users using insert-sort in ascending order */
	select_sort_asc(&list, list, user_cmp, struct user, n);
}

#define __do_merge_sort_r_xy_not_null(x, y, fn, cb) \
({ \
	(x) == NULL ? (y): (y) == NULL ? (x): fn((x), (y), (cb)); \
})
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
merge_sort_asc_recursive(struct list *self, int (*cmp)(struct node *, struct node *))
{
	if (list_empty(self) || list_singular(self))
		return;
	struct node *x = list_disable_prev(self);
	struct node *y = do_merge_sort_asc_r(x, cmp);
	list_enable_prev(self, y);
}

_unused static void
test_merge_sort_asc_recursive(void)
{
	/* initialize user database because we want stable sequential access */
	load_users_csv();
	/* sort users using merge-sort in ascending order */
	merge_sort_asc_recursive(&list, user_node_cmp);
}

_unused static void
test_merge_sort_asc_iterative(void)
{
	/* initialize user database because we want stable sequential access */
	load_users_csv();
	/* merge-sort users in ascending order */
	//merge_sort_asc(&list, list, user_node_cmp);
	merge_sort_asc(&list, list, user_cmp, struct user, n);
}

_unused static void
test_invers_asc(void)
{
	printf("Running iterative check inversions: ");
	unsigned int c = invers_asc(&list,list,user_cmp, struct user, n);
	printf("%s\n", c ? "failed": "ORDER-ASCENDING");
}

int 
main(int argc, char *argv[]) 
{
	load_users_csv();

	BENCHMARK_PRINT(bench,test_insert_sort(),
	"Running iterative insert-sort over intrusive list size: %d", users);
	BENCHMARK_PRINT(bench,test_insert_sort(),
	"Running iterative select-sort over intrusive list size: %d", users);
	BENCHMARK_PRINT(bench,test_merge_sort_asc_recursive(),
	"Running recursive merge-sort  over intrusive list size: %d", users);

//	list_for_each(list, it, struct user, n) user_print_ln(it);
//	test_invers_asc();

	BENCHMARK_PRINT(bench,test_merge_sort_asc_iterative(),
	"Running iterative merge-sort  over intrusive list size: %d", users);

//	list_for_each(list, it, struct user, n) user_print_ln(it);

//	test_invers_asc();

	return 0;
}
