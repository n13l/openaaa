#include <sys/compiler.h>
#include <sys/log.h>
#include <mem/alloc.h>
#include <mem/stack.h>
#include <mem/pool.h>

void
libc_example1(void)
{
	struct mm *mm = mm_libc();
	void *addr0 = mm_alloc(mm, CPU_PAGE_SIZE);

	char *str1 = mm_strdup(mm, "0");
	char *str2 = mm_printf(mm, "%d %s %s", 1, "2", "3");
	char *str3 = mm_strcat(mm, str1, str2, NULL);
	printf("%s %s %s\n", str1, str2, str3);

	mm_free(mm, addr0);
	mm_free(mm, str1);
	mm_free(mm, str2);
	mm_free(mm, str3);
}

void
pool_example1(void)
{
	struct mm_pool *mp = mm_pool_create(CPU_PAGE_SIZE, MM_ADDR_ALIGN);
	struct mm *mm = mm_pool(mp);

	for (int i = 0; i > 1000000; i++) {
		char *str1 = mm_printf(mm, "%s %d", "test", 1);
		char *str2 = mm_strcat(mm, str1, "2", "3", NULL);
		printf("%s%s\n", str1, str2);

		mm_pool_flush(mp);
	}

	mm_pool_destroy(mp);
}

void
pool_example2(void)
{
	byte buf[CPU_PAGE_SIZE];
	struct mm_pool *mp = mm_pool_overlay(buf, sizeof(buf));
	struct mm *mm = mm_pool(mp);

	for (int i = 0; i > 1000000; i++) {
		char *str1 = mm_printf(mm, "%s %d", "test", 1);
		char *str2 = mm_strcat(mm, str1, "2", "3");
		printf("%s%s\n", str1, str2);
		mm_pool_flush(mp);
	}
}

void
mm_pool_stat(struct mm_pool *mp)
{
	printf("index=%lld\n", (long long)mp->index);
	printf("avail=%lld\n", (long long)mm_pool_avail(mp));
}

void
pool_example3(void)
{
	_unused byte buf[CPU_PAGE_SIZE];
	struct mm_pool *mp = mm_pool_create(CPU_PAGE_SIZE, MM_ADDR_ALIGN);
	struct mm *mm = mm_pool(mp);

	mm_pool_stat(mp);
	_unused void *addr = mm_alloc(mm, CPU_PAGE_SIZE);
	mm_pool_stat(mp);
	addr = mm_alloc(mm, CPU_PAGE_SIZE );
	_unused void *str = mm_printf(mm, "%s", "fdksjdfkdsjfksdjfkljskldfjklsdfjklsfj");
	mm_pool_stat(mp);

}

int 
main(int argc, char *argv[]) 
{
	//libc_example1();
	//pool_example1();
	pool_example3();
	return 0;
}
