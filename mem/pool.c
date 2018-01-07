#include <sys/compiler.h>
#include <sys/cpu.h>
#include <mem/debug.h>
#include <mem/alloc.h>
#include <mem/pool.h>
	
void *
pool_malloc(struct mm *mm, size_t size)
{
	struct mm_pool *mp = __container_of(mm, struct mm_pool, mm);
	return mm_pool_alloc(mp, size);
}

void
pool_free(struct mm *mm, void *addr)
{
}

void *
pool_realloc(struct mm *mm, void *addr, size_t size)
{
	return NULL;
}

struct mm mm_pool_ops = {
	.alloc   = pool_malloc,
	.free    = pool_free,
	.realloc = pool_realloc,
};

struct mm *mm_pool(struct mm_pool *mp)
{
	return mp->mm;
}
