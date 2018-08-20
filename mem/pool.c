#include <sys/compiler.h>
#include <sys/cpu.h>
#include <mem/alloc.h>
#include <mem/pool.h>
	
void *
__pool_alloc_block(struct mm_pool *pool, size_t size)
{
	struct mm_vblock *block;
	size_t aligned = align_to(size, CPU_ADDR_ALIGN);

	block = (struct mm_vblock *)vm_vblock_alloc(aligned);
	slist_add((struct snode *)pool->save.final[1], &block->node);

	pool->index = 1;
	pool->save.final[1] = block;
	pool->save.avail[1] = aligned - size;
	return pool->final = (void *)((u8*)block - aligned);
}

void *
__pool_alloc_avail(struct mm_pool *pool, size_t size, size_t avail)
{
	pool->save.avail[0] = avail - size;
	return (u8*)pool->save.final[0] - avail;
}

void *
mm_pool_alloc(struct mm_pool *pool, size_t size)
{
	mem_pool_dbg("size=%d avail=%d", (int)size, (int)pool->save.avail[0]);
	if (size <= pool->save.avail[0]) {
		void *p = (u8 *)pool->save.final[0] - pool->save.avail[0];
		pool->save.avail[0] -= size;
		return p;
	} 
	return __pool_alloc_block(pool, size);
}

void
mm_pool_free(void *addr)
{
}

void *
mm_pool_end(struct mm_pool *p, void *end);

size_t
mm_pool_size(struct mm_pool *p)
{
	return 0;
}

void *
mm_pool_zalloc(struct mm_pool *pool, size_t size)
{
	void *addr = mm_pool_alloc(pool, size);
	memset(addr, 0, size);
	return addr;
}

void *
mm_pool_realloc(struct mm_pool *pool, void *addr, size_t size)
{
	pool->index = addr == pool->final;
	size_t avail = ((byte *)pool->save.final[pool->index] - (byte *)addr);
	avail -= pool->save.avail[pool->index];
	pool->save.avail[pool->index] += avail;

	addr = mm_pool_extend(pool, size);
	mm_pool_end(pool, (byte *)addr + size);
	return addr;
}

void
mm_pool_destroy(struct mm_pool *pool)
{
	struct mm_vblock *it, *block;
	mem_pool_dbg("pool %p destroyed", pool);

	block = (struct mm_vblock *)pool->save.final[1];
	slist_for_each_delsafe(block, node, it)
		vm_vblock_free(block);

	block = (struct mm_vblock *)pool->avail;
	slist_for_each_delsafe(block, node, it)
		vm_vblock_free(block);

	block = (struct mm_vblock *)pool->save.final[0];
	slist_for_each_delsafe(block, node, it)
		vm_vblock_free(block);
}

void
mm_pool_flush(struct mm_pool *pool)
{
	struct mm_vblock *it, *block;

	block = (struct mm_vblock *)pool->save.final[1];
	slist_for_each_delsafe(block, node, it)
		vm_vblock_free(block);

	block = (struct mm_vblock *)pool->save.final[0];
	slist_for_each_delsafe(block, node, it) {
		if ((void *)((u8*)block - block->size) == pool)
			break;
		slist_add((struct snode *)pool->avail, &block->node);
		pool->avail = block;
	}

	pool->save.final[0] = block;
	pool->save.avail[0] = block ? block->size - sizeof(*pool) : 0;
	pool->save.final[1] = NULL;
	pool->save.avail[1] = 0;
	pool->final = &pool->final;

	snode_init(&pool->save.node);
}

struct mm_pool *
mm_pool_overlay(void *block, size_t blocksize)
{
	size_t size, aligned = align_addr(sizeof(void *));
	size = __max(blocksize, CPU_CACHE_LINE + aligned);
	size = align_to(size, CPU_PAGE_SIZE) - aligned;

	struct mm_pool *pool = (struct mm_pool *)((u8 *)block - size);

	mem_pool_dbg("pool %p attached with %llu bytes", 
	             pool, (unsigned long long)blocksize);

	pool->save.avail[0] = size - sizeof(*pool);
	pool->save.final[0] = block;

	pool->final = &pool->final;
	pool->total_bytes  = blocksize + aligned;
	pool->blocksize = size; 
	//pool->flags |= (MM_NO_DIE | MM_NO_GROW);

	return pool;
}
	
struct mm_pool *
mm_pool_create(size_t blocksize, int flags)
{
	struct mm_vblock *block;
	size_t size, aligned = align_addr(sizeof(*block));

	size = __max(blocksize, CPU_CACHE_LINE + aligned);
	size = align_to(size, CPU_PAGE_SIZE) - aligned;

	block = (struct mm_vblock *)vm_vblock_alloc(size);
	struct mm_pool *pool = (struct mm_pool *)((u8 *)block - size);

	mem_pool_dbg("pool %p created with %llu bytes", 
	             pool, (unsigned long long)blocksize);

	pool->save.avail[0] = size - sizeof(*pool);
	pool->save.final[0] = block;

	pool->final = &pool->final;
	pool->total_bytes  = block->size + aligned;
	pool->blocksize = size;
	memcpy(&pool->mm,  &mm_pool_ops, sizeof(mm_pool_ops));

	return pool;
}

void *
mm_pool_addr(struct mm_pool *mp)
{
	return (u8 *)mp->save.final[mp->index] - mp->save.avail[mp->index];
}
                                                                                
size_t
mm_pool_avail(struct mm_pool *mp)
{
	return mp->save.avail[mp->index];
}

void *
mm_pool_start(struct mm_pool *pool, size_t size)
{
	size_t avail = aligned_part(pool->save.avail[0], CPU_ADDR_ALIGN);
	if (size <= avail) {
		pool->index = 0;
		pool->save.avail[0] = avail;
		return (byte *)pool->save.final[0] - avail;
	} else {
		void *ptr = mm_pool_alloc(pool, size);
		pool->save.avail[pool->index] += size;
		return ptr;
	}
} 

void *
mm_pool_end(struct mm_pool *mp, void *end)
{
	void *p = mm_pool_addr(mp);
	mp->save.avail[mp->index] = (u8*)mp->save.avail[mp->index] - (u8*)end;
	return p;
}

void *
mm_pool_extend(struct mm_pool *mp, size_t size)
{
	size_t avail = mm_pool_avail(mp);
	if (size <= avail)
		return mm_pool_addr(mp);

	void *ptr = mm_pool_addr(mp);
	if (mp->index) {
		size_t amortized = avail * 2;
		amortized = __max(amortized, size);
		amortized = align_to(amortized, CPU_ADDR_ALIGN);

		struct mm_vblock *block = (struct mm_vblock *)mp->save.final[1];
	        struct mm_vblock *next  = (struct mm_vblock *)block->node.next;

		mp->total_bytes = mp->total_bytes - block->size + amortized;

		size_t aligned = align_addr(sizeof(*block)) + amortized;
		ptr = vm_vblock_extend(ptr, avail, aligned);
		block = (struct mm_vblock *)(((u8*)ptr) + amortized);

		block->node.next = (struct snode *)next;
		block->size = amortized;

		mp->save.final[1] = block;
		mp->save.avail[1] = amortized;
		mp->final = ptr;
		return ptr;
	} 

	void *addr = mm_pool_alloc(mp, size);
	mp->save.avail[mp->index] += size;
	memcpy(addr, ptr, avail);
	return addr;
}

static char *
mm_pool_vprintf_at(struct mm_pool *mp, size_t pos, const char *fmt, va_list args)
{
	char *b = (char *)mm_pool_extend(mp, pos + 1) + pos;
	size_t avail = mm_pool_avail(mp);
	size_t rest = avail - pos;

	va_list args2;
	va_copy(args2, args);
	int len = vsnprintf(b, rest, fmt, args2);
	va_end(args2);

	if (len >= rest) {
		b = (char *)mm_pool_extend(mp, pos + len + 1) + pos;
		va_copy(args2, args);
		vsnprintf(b, len + 1, fmt, args2);
		va_end(args2);
	}

	mm_pool_end(mp, b + len + 1);
	return b - pos;
}

char *
mm_pool_vprintf(struct mm_pool *mp, const char *fmt, va_list args)
{
	mm_pool_start(mp, 1);
	return mm_pool_vprintf_at(mp, 0, fmt, args);
}

char *
mm_pool_printf(struct mm_pool *p, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	char *addr = mm_pool_vprintf(p, fmt, args);
	va_end(args);
	return addr;
}

char *
mm_pool_strdup(struct mm_pool *p, const char *str)
{
	size_t len = strlen(str);
	char *s = (char *)mm_pool_alloc(p, len + 1);
	memcpy(s, str, len);
	s[len] = 0;
	return s;
}

char *
mm_pool_strndup(struct mm_pool *p, const char *str, size_t len)
{
	char *s = (char *)mm_pool_alloc(p, len + 1);
	memcpy(s, str, len);
	s[len] = 0;
	return s;
}

char *
mm_pool_strmem(struct mm_pool *p, const char *str, size_t len)
{
	char *s = (char *)mm_pool_alloc(p, len + 1);
	memcpy(s, str, len);
	s[len] = 0;
	return s;
}

char *
mm_pool_memdup(struct mm_pool *p, const char *ptr, size_t len)
{
	char *s = (char *)mm_pool_alloc(p, len);
	memcpy(s, ptr, len);
	return s;
}


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
	return &mp->mm;
}
