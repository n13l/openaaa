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

static inline void user_print(struct user *x)
{
	printf("%s:%s:%s:%s:%s\n", 
	       x->first, x->last, x->race, x->gender, x->email);
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

		if (users>=10000)
			break;
	}

	if (line)
		free(line);

	fclose(fd);

	BENCHMARK_INIT(bench);
}

static void
test_default_sort(void)
{
	/* initialize user database because we want stable sequential access */
	load_users_csv();
	/* sort users using bubble sort in ascending order */
	list_sort_asc(&list, user_cmp, struct user, n);
}

static void
test_bubble_sort(void)
{
	/* initialize user database because we want stable sequential access */
	load_users_csv();
	/* sort users using bubble-sort in ascending order */
	bubble_sort_asc(&list, list, user_cmp, struct user, n);
}

static void
test_merge_sort(void)
{
	/* initialize user database because we want stable sequential access */
	load_users_csv();
	/* sort users using merge-sort in ascending order */
	bubble_sort_asc(&list, list, user_cmp, struct user, n);
}

int 
main(int argc, char *argv[]) 
{
	load_users_csv();

	BENCHMARK_PRINT(bench,test_bubble_sort(),
	                "Running bubble-sort for %d users. ", users);
	BENCHMARK_PRINT(bench,test_merge_sort(),
	                "Running merge-sort for %d users. ", users);
	BENCHMARK_PRINT(bench,test_bubble_sort(),
	                "Running quick-sort for %d users. ", users);
	BENCHMARK_PRINT(bench,test_default_sort(),
	                "Running default sort for %d users. ", users);
	
	list_for_each(list, it, struct user, n)
		user_print(it);

	return 0;
}
