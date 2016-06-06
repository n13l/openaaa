/*
 *	UCW Library -- Memory Pools (One-Time Allocation)
 *
 *	(c) 1997--2001 Martin Mares <mj@ucw.cz>
 *	(c) 2007 Pavel Charvat <pchar@ucw.cz>
 *
 *      Adaptation for AAA library:
 *      (c) 2013 Daniel Kubec <niel@rtfm.cz>
 *
 *	This software may be freely distributed and used according to the terms
 *	of the GNU Lesser General Public License.
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <sys/compiler.h>
#include <sys/cpu.h>
#include <mem/alloc.h>
#include <mem/pool.h>

#define MP_CHUNK_TAIL _align_to(sizeof(struct mempool_chunk), CPU_STRUCT_ALIGN)
#define MP_SIZE_MAX (~0U - MP_CHUNK_TAIL - CPU_PAGE_SIZE)

struct mempool_chunk {
	struct mempool_chunk *next;
	unsigned int size;
};

unsigned int
mp_size_max(void)
{
	return MP_SIZE_MAX;
}

static unsigned int
mp_align_size(unsigned int size)
{
#ifdef MEM_POOL_MMAP
	return _align_to(size + MP_CHUNK_TAIL, CPU_PAGE_SIZE) - MP_CHUNK_TAIL;
#else
	return _align_to(size, CPU_STRUCT_ALIGN);
#endif
}

void
mp_init(struct mempool *pool, uint chunk_size)
{
	chunk_size = mp_align_size(_max(sizeof(struct mempool), chunk_size));
	*pool = (struct mempool) {
		.chunk_size = chunk_size,
		.threshold = chunk_size >> 1,
		.last_big = &pool->last_big 
	};
}

static void *
mp_new_big_chunk(uint size)
{
	void *addr = xmalloc(size + MP_CHUNK_TAIL);
	struct mempool_chunk *chunk;
	chunk = (struct mempool_chunk *)(((byte*)addr) + size);
	chunk->size = size;
	return chunk;
}

static void
mp_free_big_chunk(struct mempool_chunk *chunk)
{
	xfree((void *)((char *)chunk - chunk->size));
}

static void *
mp_new_chunk(uint size)
{
#ifdef MEM_POOL_MMAP
	struct mempool_chunk *chunk;
	chunk = page_alloc(size + MP_CHUNK_TAIL) + size;
	chunk->size = size;
	return chunk;
#else
	return mp_new_big_chunk(size);
#endif
}

static void
mp_free_chunk(struct mempool_chunk *chunk)
{
#ifdef MEM_POOL_MMAP
	page_free((void *)chunk - chunk->size, chunk->size + MP_CHUNK_TAIL);
#else
	mp_free_big_chunk(chunk);
#endif
}

struct mempool *
mp_new(unsigned int chunk_size)
{
	chunk_size = mp_align_size(_max(sizeof(struct mempool), chunk_size));
	struct mempool_chunk *chunk = mp_new_chunk(chunk_size);
	struct mempool *pool = (void *)((char *)chunk - chunk_size);

	mem_dbg("creating mempool %p with %u bytes long chunks", 
	        pool, chunk_size);

	chunk->next = NULL;

	*pool = (struct mempool) {
	.state = { .free = { chunk_size - sizeof(*pool) }, .last = { chunk } },
	.chunk_size = chunk_size,
	.threshold = chunk_size >> 1,
	.last_big = &pool->last_big 
	};

	return pool;
}

static void
mp_free_chain(struct mempool_chunk *chunk)
{
	while (chunk) {
		struct mempool_chunk *next = chunk->next;
		mp_free_chunk(chunk);
		chunk = next;
	}
}

static void
mp_free_big_chain(struct mempool_chunk *chunk)
{
	while (chunk) {
		struct mempool_chunk *next = chunk->next;
		mp_free_big_chunk(chunk);
		chunk = next;
	}
}

void
mp_delete(struct mempool *pool)
{
	mem_dbg("deleting mempool %p", pool);
	mp_free_big_chain(pool->state.last[1]);
	mp_free_chain(pool->unused);
	mp_free_chain(pool->state.last[0]);
}

void
mp_flush(struct mempool *pool)
{
	mp_free_big_chain(pool->state.last[1]);
	struct mempool_chunk *chunk, *next;
	for (chunk = pool->state.last[0]; 
	     chunk && (void *)((char *)chunk - chunk->size) != pool; 
	     chunk = next) {
		next = chunk->next;
		chunk->next = pool->unused;
		pool->unused = chunk;
	}

	pool->state.last[0] = chunk;
	pool->state.free[0] = chunk ? chunk->size - sizeof(*pool) : 0;
	pool->state.last[1] = NULL;
	pool->state.free[1] = 0;
	pool->state.next = NULL;
	pool->last_big = &pool->last_big;
}

static void
mp_stats_chain(struct mempool_chunk *chunk, 
               struct mempool_stats *stats, unsigned int idx)
{
	while (chunk) {
		stats->chain_size[idx] += chunk->size + sizeof(*chunk);
		stats->chain_count[idx]++;
		chunk = chunk->next;
	}

	stats->total_size += stats->chain_size[idx];
}

void
mp_stats(struct mempool *pool, struct mempool_stats *stats)
{
	memset(stats, 0, sizeof(*stats));
	mp_stats_chain(pool->state.last[0], stats, 0);
	mp_stats_chain(pool->state.last[1], stats, 1);
	mp_stats_chain(pool->unused, stats, 2);
}

u64
mp_total_size(struct mempool *pool)
{
	struct mempool_stats stats;
	mp_stats(pool, &stats);
	return stats.total_size;
}

void *
mp_alloc_internal(struct mempool *pool, uint size)
{
	struct mempool_chunk *chunk;
	if (size <= pool->threshold) {
		pool->index = 0;
		if (pool->unused) {
			chunk = pool->unused;
			pool->unused = chunk->next;
		} else
			chunk = mp_new_chunk(pool->chunk_size);

		chunk->next = pool->state.last[0];
		pool->state.last[0] = chunk;
		pool->state.free[0] = pool->chunk_size - size;
		return (void *)((char *)chunk - pool->chunk_size);
	} else if (likely(size <= MP_SIZE_MAX)) {
		pool->index = 1;
		unsigned int aligned = _align_to(size, CPU_STRUCT_ALIGN);
		chunk = mp_new_big_chunk(aligned);
		chunk->next = pool->state.last[1];
		pool->state.last[1] = chunk;
		pool->state.free[1] = aligned - size;
		return pool->last_big = (void *)((char *)chunk - aligned);
	} else
		die("Cannot allocate %u bytes from a mempool", size);

	return NULL;
}

void *
mp_alloc(struct mempool *pool, unsigned int size)
{
	return mp_alloc_fast(pool, size);
}

void *
mp_alloc_noalign(struct mempool *pool, unsigned int size)
{
	return mp_alloc_fast_noalign(pool, size);
}

void *
mp_alloc_zero(struct mempool *pool, unsigned int size)
{
	void *ptr = mp_alloc_fast(pool, size);
	memset(ptr, 0, size);
	return ptr;
}

void *
mp_start_internal(struct mempool *mp, unsigned int size)
{
	void *ptr = mp_alloc_internal(mp, size);
	mp->state.free[mp->index] += size;
	return ptr;
}

void *
mp_start(struct mempool *pool, unsigned int size)
{
	return mp_start_fast(pool, size);
}

void *
mp_start_noalign(struct mempool *pool, unsigned int size)
{
	return mp_start_fast_noalign(pool, size);
}

void *
mp_grow_internal(struct mempool *pool, unsigned int size)
{
	if (unlikely(size > MP_SIZE_MAX))
		die("Cannot allocate %u bytes of memory", size);

	unsigned int avail = mp_avail(pool);
	void *ptr = mp_ptr(pool);

	if (!pool->index) {
		void *p = mp_start_internal(pool, size);
		memcpy(p, ptr, avail);
		return p;		
	}

	uint amortized = likely(avail <= MP_SIZE_MAX / 2) ? avail * 2 : MP_SIZE_MAX;
	amortized = _max(amortized, size);
	amortized = _align_to(amortized, CPU_STRUCT_ALIGN);
	struct mempool_chunk *chunk = pool->state.last[1], *next = chunk->next;
	ptr = realloc(ptr, amortized + MP_CHUNK_TAIL);
	chunk = (struct mempool_chunk *)((char *)ptr + amortized);
	chunk->next = next;
	chunk->size = amortized;
	pool->state.last[1] = chunk;
	pool->state.free[1] = amortized;
	pool->last_big = ptr;
	return ptr;
}

uint
mp_open(struct mempool *pool, void *ptr)
{
	return mp_open_fast(pool, ptr);
}

void *
mp_realloc(struct mempool *pool, void *ptr, unsigned int size)
{
	return mp_realloc_fast(pool, ptr, size);
}

void *
mp_realloc_zero(struct mempool *pool, void *ptr, unsigned int size)
{
	unsigned int old_size = mp_open_fast(pool, ptr);
	ptr = mp_grow(pool, size);
	if (size > old_size)
		memset((char *)ptr + old_size, 0, size - old_size);
	mp_end(pool, (char *)ptr + size);
	return ptr;
}

void *
mp_spread_internal(struct mempool *pool, void *p, unsigned int size)
{
	void *old = mp_ptr(pool);
	void *new = mp_grow_internal(pool, ((char *)p - (char *)old + size));
	return ((char *)p - (char *)old + (char *)new);
}

void
mp_restore(struct mempool *pool, struct mempool_state *state)
{
	struct mempool_chunk *chunk, *next;
	struct mempool_state s = *state;
	for (chunk = pool->state.last[0]; chunk != s.last[0]; chunk = next) {
		next = chunk->next;
		chunk->next = pool->unused;
		pool->unused = chunk;
	}

	for (chunk = pool->state.last[1]; chunk != s.last[1]; chunk = next) {
		next = chunk->next;
		mp_free_big_chunk(chunk);
	}

	pool->state = s;
	pool->last_big = &pool->last_big;
}

struct mempool_state *
mp_push(struct mempool *mp)
{
	struct mempool_state state = mp->state;
	struct mempool_state *p = mp_alloc_fast(mp, sizeof(*p));
	*p = state;
	mp->state.next = p;
	return p;
}

void
mp_pop(struct mempool *pool)
{
	assert(pool->state.next);
	mp_restore(pool, pool->state.next);
}

char *
mp_strdup(struct mempool *p, const char *s)
{
	if (!s)
		return NULL;

	unsigned int l = strlen(s) + 1;
	char *t = mp_alloc_fast_noalign(p, l);
	memcpy(t, s, l);
	return t;
}

void *
mp_memdup(struct mempool *p, const void *s, unsigned int len)
{
	void *t = mp_alloc_fast(p, len);
	memcpy(t, s, len);
	return t;
}

char *
mp_multicat(struct mempool *p, ...)
{
	va_list args, a;
	va_start(args, p);
	char *x, *y;
	uint cnt = 0;
	va_copy(a, args);

	while ((x = va_arg(a, char *)))
		cnt++;

	uint *sizes = alloca(cnt * sizeof(uint));
	uint len = 1;
	cnt = 0;
	va_end(a);
	va_copy(a, args);

	while ((x = va_arg(a, char *)))
		len += sizes[cnt++] = strlen(x);

	char *buf = mp_alloc_fast_noalign(p, len);
	y = buf;
	va_end(a);
	cnt = 0;

	while ((x = va_arg(args, char *))) {
		memcpy(y, x, sizes[cnt]);
		y += sizes[cnt++];
	}

	*y = 0;
	va_end(args);
	return buf;
}

char *
mp_strjoin(struct mempool *p, char **a, unsigned int n, unsigned int sep)
{
	unsigned int sizes[n];
	unsigned int len = 1;

	for (unsigned int i = 0; i<n; i++)
		len += sizes[i] = strlen(a[i]);

	if (sep && n)
		len += n-1;

	char *dest = mp_alloc_fast_noalign(p, len);
	char *d = dest;
	for (unsigned int i = 0; i<n; i++) {
		if (sep && i)
			*d++ = sep;

		memcpy(d, a[i], sizes[i]);
		d += sizes[i];
	}

	*d = 0;
	return dest;
}

char *
mp_strmem(struct mempool *a, const void *mem, unsigned int len)
{
	char *str = mp_alloc_noalign(a, len+1);
	memcpy(str, mem, len);
	str[len] = 0;
	return str;
}

static char *
mp_vprintf_at(struct mempool *mp, uint ofs, const char *fmt, va_list args)
{
	char *ret = (char *)mp_grow(mp, ofs + 1) + ofs;
	va_list args2;
	va_copy(args2, args);
	int cnt = vsnprintf(ret, mp_avail(mp) - ofs, fmt, args2);
	va_end(args2);

	if (cnt < 0) {
		do {
			ret = (char *)mp_expand(mp) + ofs;
			va_copy(args2, args);
			cnt = vsnprintf(ret, mp_avail(mp) - ofs, fmt, args2);
			va_end(args2);
		} while (cnt < 0);
	} else if ((unsigned int )cnt >= mp_avail(mp) - ofs) {
		ret = (char *)mp_grow(mp, ofs + cnt + 1) + ofs;
		va_copy(args2, args);
		int cnt2 = vsnprintf(ret, cnt + 1, fmt, args2);
		va_end(args2);
		assert(cnt2 == cnt);
	}

	mp_end(mp, ret + cnt + 1);
	return ret - ofs;
}

char *
mp_vprintf(struct mempool *mp, const char *fmt, va_list args)
{
	mp_start(mp, 1);
	return mp_vprintf_at(mp, 0, fmt, args);
}

char *
mp_printf(struct mempool *p, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	char *res = mp_vprintf(p, fmt, args);
	va_end(args);
	return res;
}

char *
mp_vprintf_append(struct mempool *mp, char *ptr, const char *fmt, va_list args)
{
	uint ofs = mp_open(mp, ptr);
	assert(ofs && !ptr[ofs - 1]);
	return mp_vprintf_at(mp, ofs - 1, fmt, args);
}

char *
mp_printf_append(struct mempool *mp, char *ptr, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	char *res = mp_vprintf_append(mp, ptr, fmt, args);
	va_end(args);
	return res;
}
