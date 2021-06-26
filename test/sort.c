#if 0
#include <sys/compiler.h>
#include <sys/cpu.h>
#include <sys/log.h>
#include <list.h>
#include <sys/timestamp.h>
#include <stdlib.h>
#include <string.h>

DEFINE_BENCHMARK(bench);
DEFINE_LIST(list);

static struct myuser *db;

struct myuser {
	char first[32];
	char last[32];
	char gender[32];
	char race[32];
	char email[32];
	char ip[32];
	struct node n;
};

unsigned int db_size = sizeof(struct myuser) * 100000;
unsigned int users = 0;
unsigned int items = 0;

void
merge_sort_asc_recursive(struct dlist *, int (*fb)(struct node *, struct node *));

static inline int user_cmp(struct myuser *a, struct myuser *b)
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
	struct myuser *a = __container_of(x, struct myuser, n); 
	struct myuser *b = __container_of(y, struct myuser, n);
	int cmp;
	if ((cmp = strcmp(a->first, b->first)))
		return cmp;
	if ((cmp = strcmp(a->last, b->last)))
		return cmp;
	return 0;
}


_unused static inline void user_print_ln(struct myuser *x)
{
	printf("%s:%s\n", x->first, x->last);
}

_unused static inline void user_print(struct myuser *x)
{
	printf("%s:%s ", x->first, x->last);
}

static inline void
parse_line(int index, char *arg, ssize_t len) 
{
	struct myuser *user = db + index;
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

	dlist_add(&list, &user->n);
}

static void
load_users_csv(void)
{
	dlist_init(&list);
	users = 0;
	db = db?:malloc(db_size);

	FILE *fd; char *line = NULL;
	ssize_t nr; size_t len = 0;
	if (!(fd = fopen("test/users.csv", "rb")))
		return;
        while ((nr = getline(&line, &len, fd)) != -1) {
		if (users >= items )
			break;
		parse_line(++users, line, len);
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
	dlist_sort_asc(&list, user_cmp, struct myuser, n);
}

_unused static void
test_array_sort(void)
{
	/* initialize user database because we want stable sequential access */
	load_users_csv();
	/* sort users using insert-sort in ascending order */
	insert_sort_asc(&list, list, user_cmp, struct myuser, n);
}

_unused static void
test_insert_sort(void)
{
	load_users_csv();
	/* sort users using insert-sort in ascending order */
	insert_sort_asc(&list, list, user_cmp, struct myuser, n);
}

_unused static void
test_select_sort(void)
{
	load_users_csv();
	/* sort users using insert-sort in ascending order */
	select_sort_asc(&list, list, user_cmp, struct myuser, n);
}

_unused static void
test_merge_sort_asc_recursive(void)
{
	load_users_csv();
	/* sort users using merge-sort in ascending order */
	merge_sort_asc_recursive(&list, user_node_cmp);
}

_unused static void
test_merge_sort_asc_iterative(void)
{
	load_users_csv();
	/* merge-sort users in ascending order */
	merge_sort_asc(&list, list, user_cmp, struct myuser, n);
}

_unused static void
test_invers_asc(void)
{
	printf("Running iterative check inversions: ");
	unsigned int c = invers_asc(&list,list,user_cmp, struct myuser, n);
	printf("%s\n", c ? "failed": "ORDER-ASCENDING");
}

int 
main(int argc, char *argv[]) 
{
	items = argc > 1 ? atoi(argv[1]): 0;
	load_users_csv();

	BENCHMARK_PRINT(bench,test_insert_sort(),
	"Running iterative insert-sort over intrusive list size: %d", users);
	BENCHMARK_PRINT(bench,test_insert_sort(),
	"Running iterative select-sort over intrusive list size: %d", users);
	BENCHMARK_PRINT(bench,test_merge_sort_asc_recursive(),
	"Running recursive merge-sort  over intrusive list size: %d", users);
	BENCHMARK_PRINT(bench,test_merge_sort_asc_iterative(),
	"Running iterative merge-sort  over intrusive list size: %d", users);

	if (argc > 2) dlist_for_each(list, it, struct myuser, n)
		user_print_ln(it);

	unsigned int s1 = dlist_size(&list);
	dlist_ddup(&list, user_cmp, struct myuser, n);
	unsigned int s2 = dlist_size(&list);

	if (argc > 2) dlist_for_each(list, it, struct myuser, n)
		user_print_ln(it);

	if (argc > 2 && (s1 - s2))
		printf("duplicates: %d\n", (s1 - s2));

	return 0;
}

#else

int 
main(int argc, char *argv[]) 
{
	return 0;
}

#endif
