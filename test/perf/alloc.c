#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include <sys/compiler.h>
#include <sys/cpu.h>
#include <mem/alloc.h>
#include <mem/safe.h>

#include <unix/timespec.h>

#define OP_LIBC_ALLOC_HEAP       1
#define OP_MM_ALLOC_STACK      2
#define OP_MM_ALLOC_POOL       3

_unused static const char * const buf_names[] = {
	[CPU_CACHE_LINE]     = "cpu_cache_line",
	[CPU_PAGE_SIZE]      = "cpu_page_size"
};

_unused static const char * const ops_names[] = {
	[OP_LIBC_ALLOC_HEAP] = "mm_alloc  type=stack",
	[OP_MM_ALLOC_STACK]  = "mm_alloc  type=pool ",
	[OP_MM_ALLOC_POOL]   = "std_alloc type=heap ",
};

const int iterations = 1000000;
const int operations = 20;

#ifndef CLOCK_REALTIME
#define CLOCK_REALTIME 1
#endif

#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC 2
#endif

void
alloc_pool(struct mm_pool *pool, size_t size)
{
	for (int i = 0; i < operations; i++) {	
		char *p = mm_alloc(pool, CPU_CACHE_LINE);
		volatile u8 *u = (u8*)p; *u = 0;
	}
	mm_flush(pool);
}

void
test_alloc_pool(struct mm_pool *pool, size_t size, long long unsigned iter)
{
	timestamp_t start = get_timestamp();

	for(int i = 0; i < iter; i++)
		alloc_pool(pool, size);

	u64 delta = get_timestamp() - start;
	_unused float avg = (delta / (float) iter);

	info("built-in alloc type=pool  size=%.5d  allocs=%d avg=%.1f ns", 
		(int)size, operations * iterations, avg);
}

void
alloc_heap(size_t size)
{
	for (int i = 0; i < operations; i++) {
		char *p = malloc(CPU_CACHE_LINE);
		volatile u8 *u = (u8*)p; *u = 0;
		free(p);
	}
}

void
test_alloc_heap(size_t size, long long unsigned iter)
{
	timestamp_t start = get_timestamp();

	for(int i = 0; i < iter; i++)
		alloc_heap(size);

	u64 delta = get_timestamp() - start;
	_unused float avg = (delta / (float) iter);

	info("libc-std alloc type=heap  size=%.5d  allocs=%d avg=%.1f ns", 
		(int)size, operations * iterations, avg);
}

void
alloc_stack(size_t size)
{
	for (int i = 0; i < 20; i++) {
		char *p = alloca(CPU_CACHE_LINE);
		volatile u8 *u = (u8*)p; *u = 0;
	}
}

void
test_alloc_stack(size_t size, long long unsigned iter)
{
	timestamp_t start = get_timestamp();

	for(int i = 0; i < iter; i++)
		alloc_stack(size);

	u64 delta = get_timestamp() - start;
	_unused float avg = (delta / (float) iter);

	info("built-in alloc type=stack size=%.5d  allocs=%d avg=%.1f ns",
	       (int)size, operations * iterations, avg);
}

int 
main(int argc, char *argv[]) 
{
	struct mm_pool *pool = mm_pool_create(CPU_PAGE_SIZE * 40, 0);

	test_alloc_stack(CPU_CACHE_LINE, iterations);
	test_alloc_pool(pool, CPU_CACHE_LINE, iterations);
	test_alloc_heap(CPU_CACHE_LINE, iterations);

	test_alloc_stack(CPU_PAGE_SIZE, iterations);
	test_alloc_pool(pool, CPU_PAGE_SIZE, iterations);
	test_alloc_heap(CPU_PAGE_SIZE, iterations);

	test_alloc_stack(CPU_PAGE_SIZE * 4, iterations);
	test_alloc_pool(pool, CPU_PAGE_SIZE * 4, iterations);
	test_alloc_heap(CPU_PAGE_SIZE * 4, iterations);


	mm_pool_destroy(pool);
	
	return 0;
}
