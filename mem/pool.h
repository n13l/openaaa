/*
 *	UCW Library -- Memory Pools
 *
 *	(c) 1997--2005 Martin Mares <mj@ucw.cz>
 *	(c) 2007 Pavel Charvat <pchar@ucw.cz>
 *
 *      Adaptation for AAA:
 *      (c) 2013 Daniel Kubec <niel@rtfm.cz>
 *
 *	This software may be freely distributed and used according to the terms
 *	of the GNU Lesser General Public License.
 */

#ifndef __MEM_POOLS_H__
#define __MEM_POOLS_H__

#include <stdlib.h>
#include <stdarg.h>
#include <sys/compiler.h>
#include <sys/cpu.h>
#include <sys/decls.h>
#include <mem/alloc.h>

/***
 * [[defs]]
 * Definitions
 * -----------
 ***/

/**
 * Memory pool state (see @mp_push(), ...).
 * You should use this one as an opaque handle only, the insides are internal.
 **/

struct mempool_state {
	unsigned int free[2];
	void *last[2];
	struct mempool_state *next;
};

/*
 * Memory pool.
 * You should use this one as an opaque handle only, the insides are internal.
 */

struct mempool {
	struct mempool_state state;
	void *unused, *last_big;
	unsigned int chunk_size;
	unsigned int threshold;
	unsigned int index;
};

struct mempool_stats {
	u64 total_size;
	uint chain_count[3];
	uint chain_size[3];
};

/*
 * [[basic]]
 * Basic manipulation
 * ------------------
 */

/*
 * Initialize a given mempool structure.
 * @chunk_size must be in the interval `[1, UINT_MAX / 2]`.
 * It will allocate memory by this large chunks and take
 * memory to satisfy requests from them.
 *
 * Memory pools can be treated as 
 * <<trans:respools,resources>>, see <<trans:res_mempool()>>.
 */

void
mp_init(struct mempool *pool, unsigned int chunk_size);

/**
 * Allocate and initialize a new memory pool.
 * See @mp_init() for @chunk_size limitations.
 *
 * The new mempool structure is allocated on the new mempool.
 *
 * Memory pools can be treated as 
 * <<trans:respools,resources>>, see <<trans:res_mempool()>>.
 */

struct mempool *
mp_new(unsigned int size);

/**
 * Cleanup mempool initialized by mp_init or mp_new.
 * Frees all the memory allocated by this mempool and,
 * if created by @mp_new(), the @pool itself.
 **/
void mp_delete(struct mempool *mp);

/**
 * Frees all data on a memory pool, but leaves it working.
 * It can keep some of the chunks allocated to serve
 * further allocation requests. Leaves the @pool alive,
 * even if it was created with @mp_new().
 **/

void
mp_flush(struct mempool *mp);

/*
 * Compute some statistics for debug purposes.
 * See the definition of the <<struct_mempool_stats,mempool_stats structure>>.
 */

void
mp_stats(struct mempool *mp, struct mempool_stats *stats);

/* How many bytes were allocated by the pool. */

u64
mp_total_size(struct mempool *mp);	

/* For internal use only, do not call directly */
void *
mp_alloc_internal(struct mempool *mp, uint size) _malloc;

/*
 * The function allocates new @size bytes on a given memory pool.
 * If the @size is zero, the resulting pointer is undefined,
 * but it may be safely reallocated or used as the parameter
 * to other functions below.
 *
 * The resulting pointer is always aligned to a multiple of
 * `CPU_STRUCT_ALIGN` bytes and this condition remains true also
 * after future reallocations.
 */

void *
mp_alloc(struct mempool *mp, unsigned int size);

/*
 * The same as @mp_alloc(), but the result may be unaligned.
 */

void *
mp_alloc_noalign(struct mempool *mp, unsigned int size);

/*
 * The same as @mp_alloc(), but fills the newly allocated memory with zeroes.
 */

void *
mp_alloc_zero(struct mempool *mp, unsigned int size);

/*
 * Inlined version of @mp_alloc().
 */
static inline void *
mp_alloc_fast(struct mempool *mp, unsigned int size)
{
	unsigned int avail = mp->state.free[0] & ~(CPU_STRUCT_ALIGN - 1);
	if (size <= avail) {
		mp->state.free[0] = avail - size;
		return (byte *)mp->state.last[0] - avail;
	} else
		return mp_alloc_internal(mp, size);
}

/*
 * Inlined version of @mp_alloc_noalign().
 */
static inline void *
mp_alloc_fast_noalign(struct mempool *mp, unsigned int size)
{
	if (size <= mp->state.free[0]) {
		void *ptr = (byte *)mp->state.last[0] - mp->state.free[0];
		mp->state.free[0] -= size;
		return ptr;
	} else
		return mp_alloc_internal(mp, size);
}

/*
 * [[gbuf]]
 * Growing buffers
 * ---------------
 *
 * You do not need to know, how a buffer will need to be large,
 * you can grow it incrementally to needed size. You can grow only
 * one buffer at a time on a given mempool.
 *
 * Similar functionality is provided by <<growbuf:,growing buffes>> module.
 */

/* For internal use only, do not call directly */
void *
mp_start_internal(struct mempool *mp, unsigned int size) _malloc;

void *
mp_grow_internal(struct mempool *mp, unsigned int size);

void *
mp_spread_internal(struct mempool *mp, void *p, unsigned int size);

static inline uint
mp_idx(struct mempool *mp, void *ptr)
{
	return ptr == mp->last_big;
}

/*
 * Open a new growing buffer (at least @size bytes long).
 * If the @size is zero, the resulting pointer is undefined,
 * but it may be safely reallocated or used as the parameter
 * to other functions below.
 *
 * The resulting pointer is always aligned to a multiple of
 * `CPU_STRUCT_ALIGN` bytes and this condition remains true also
 * after future reallocations. There is an unaligned version as well.
 *
 * Keep in mind that you can't make any other pool allocations
 * before you "close" the growing buffer with @mp_end().
 */

void *
mp_start(struct mempool *mp, unsigned int size);

void *
mp_start_noalign(struct mempool *mp, unsigned int size);

/*
 * Inlined version of @mp_start().
 */

static inline void *
mp_start_fast(struct mempool *mp, unsigned int size)
{
	unsigned int avail = mp->state.free[0] & ~(CPU_STRUCT_ALIGN - 1);
	if (size <= avail) {
		mp->index = 0;
		mp->state.free[0] = avail;
		return (byte *)mp->state.last[0] - avail;
	} else
		return mp_start_internal(mp, size);
}

/*
 * Inlined version of @mp_start_noalign().
 */

static inline void *
mp_start_fast_noalign(struct mempool *mp, unsigned int size)
{
	if (size <= mp->state.free[0]) {
		mp->index = 0;
		return (byte *)mp->state.last[0] - mp->state.free[0];
	} else
		return mp_start_internal(mp, size);
}

/*
 * Return start pointer of the growing buffer allocated by latest 
 * @mp_start() or a similar function.
 */

static inline void *
mp_ptr(struct mempool *mp)
{
	return (byte *)mp->state.last[mp->index] - mp->state.free[mp->index];
}

/*
 * Return the number of bytes available for extending the growing buffer.
 * (Before a reallocation will be needed).
 */

static inline unsigned int
mp_avail(struct mempool *mp)
{
	return mp->state.free[mp->index];
}

/*
 * Grow the buffer allocated by @mp_start() to be at least @size bytes long
 * (@size may be less than @mp_avail(), even zero). Reallocated buffer may
 * change its starting position. The content will be unchanged to the minimum
 * of the old and new sizes; newly allocated memory will be uninitialized.
 * Multiple calls to mp_grow() have amortized linear cost wrt. the maximum 
 * value of @size. 
 */
static inline void *
mp_grow(struct mempool *mp, unsigned int size)
{
	return (size <= mp_avail(mp)) ? mp_ptr(mp) : mp_grow_internal(mp, size);
}

/*
 * Grow the buffer by at least one byte -- equivalent to 
 * <<mp_grow(),`mp_grow`>>`(@pool, @mp_avail(pool) + 1)`.
 */
static inline void *
mp_expand(struct mempool *mp)
{
	return mp_grow_internal(mp, mp_avail(mp) + 1);
}

/*
 * Ensure that there is at least @size bytes free after @p,
 * if not, reallocate and adjust @p.
 */

static inline void *
mp_spread(struct mempool *mp, void *p, unsigned int  size)
{
	return (((uint)((byte *)mp->state.last[mp->index] - 
	       (byte *)p) >= size) ? p : mp_spread_internal(mp, p, size));
}

/*
 * Close the growing buffer. The @end must point just behind the data, 
 * you want to keep allocated (so it can be in the interval 
 * `[@mp_ptr(@pool), @mp_ptr(@pool) + @mp_avail(@pool)]`).
 * Returns a pointer to the beginning of the just closed block.
 */

static inline void *
mp_end(struct mempool *mp, void *end)
{
	void *p = mp_ptr(mp);
	mp->state.free[mp->index] = (byte *)mp->state.last[mp->index]-(byte *)end;
	return p;
}

/*
 * Return size in bytes of the last allocated memory block (with @mp_alloc() or @mp_end()).
 */

static inline unsigned int 
mp_size(struct mempool *mp, void *ptr)
{
	unsigned int idx = mp_idx(mp, ptr);
	return ((byte *)mp->state.last[idx] - (byte *)ptr) - mp->state.free[idx];
}

/*
 * Open the last memory block (allocated with @mp_alloc() or @mp_end())
 * for growing and return its size in bytes. The contents and the start pointer
 * remain unchanged. Do not forget to call @mp_end() to close it.
 */

unsigned int
mp_open(struct mempool *mp, void *ptr);

/**
 * Inlined version of mp_open().
 **/

static inline uint
mp_open_fast(struct mempool *mp, void *ptr)
{
	mp->index = mp_idx(mp, ptr);
	unsigned int size = ((byte *)mp->state.last[mp->index] - (byte *)ptr) - 
	                             mp->state.free[mp->index];
	mp->state.free[mp->index] += size;
	return size;
}

/*
 * Reallocate the last memory block (allocated with @mp_alloc() or @mp_end())
 * to the new @size. Behavior is similar to @mp_grow(), but the resulting
 * block is closed.
 */

void *
mp_realloc(struct mempool *mp, void *ptr, unsigned int size);


/*
 * The same as @mp_realloc(), but fills the additional bytes 
 * (if any) with zeroes.
 */

void *
mp_realloc_zero(struct mempool *mp, void *ptr, unsigned int size);

/*
 * Inlined version of mp_realloc().
 */

static inline void *
mp_realloc_fast(struct mempool *mp, void *ptr, unsigned int size)
{
	mp_open_fast(mp, ptr);
	ptr = mp_grow(mp, size);
	mp_end(mp, (byte *)ptr + size);
	return ptr;
}

/*
 * Save the current state of a memory pool.
 * Do not call this function with an opened growing buffer.
 */
static inline void
mp_save(struct mempool *mp, struct mempool_state *state)
{
	*state = mp->state;
	mp->state.next = state;
}

/*
 * Save the current state to a newly allocated mempool_state structure.
 * Do not call this function with an opened growing buffer.
 */
struct mempool_state *
mp_push(struct mempool *mp);

/*
 * Restore the state saved by @mp_save() or @mp_push() and free all
 * data allocated after that point (including the state structure itself).
 * You can't reallocate the last memory block from the saved state.
 */
void
mp_restore(struct mempool *mp, struct mempool_state *state);

/*
 * Inlined version of @mp_restore().
 */

static inline void
mp_restore_fast(struct mempool *mp, struct mempool_state *state)
{
	if (mp->state.last[0] != state->last[0] || 
	    mp->state.last[1] != state->last[1])
		mp_restore(mp, state);
	else {
		mp->state = *state;
		mp->last_big = &mp->last_big;
	}
}

/*
 * Restore the state saved by the last call to @mp_push().
 * @mp_pop() and @mp_push() works as a stack so you can push more states safely.
 */

void
mp_pop(struct mempool *mp);

/* Makes a copy of a string on a mempool. Returns NULL for NULL string. */
char *
mp_strdup(struct mempool *mp, const char *) _malloc;

/* Makes a copy of a memory block on a mempool. */
void *
mp_memdup(struct mempool *mp, const void *, unsigned int) _malloc;
/*x*
 * Concatenates all passed strings. The last parameter must be NULL.
 * This will concatenate two strings:
 *
 *   char *message = mp_multicat(pool, "hello ", "world", NULL);
 */

char *
mp_multicat(struct mempool *, ...) _malloc _sentinel;

/*
 * Concatenates two strings and stores result on @mp.
 */

static inline char *_malloc
mp_strcat(struct mempool *mp, const char *x, const char *y)
{
	return mp_multicat(mp, x, y, (void *) NULL);
}

/*
 * Join strings and place @sep between each two neighboring.
 * @p is the mempool to provide memory, @a is array of strings and @n
 * tells how many there is of them.
 */

char *
mp_strjoin(struct mempool *p, char **a, uint n, uint sep) _malloc;
/*
 * Convert memory block to a string. Makes a copy of the given memory block
 * in the mempool @p, adding an extra terminating zero byte at the end.
 */

char *
mp_strmem(struct mempool *p, const void *mem, unsigned int len) _malloc;

/*
 * printf() into a in-memory string, allocated on the memory pool.
 */

char *
mp_printf(struct mempool *mp, const char *fmt, ...)
_format_check(printf,2,3) _malloc;
/*
 * Like @mp_printf(), but uses `va_list` for parameters.
 */
char *
mp_vprintf(struct mempool *mp, const char *fmt, va_list args) _malloc;

/*
 * Like @mp_printf(), but it appends the data at the end of string
 * pointed to by @ptr. The string is @mp_open()ed, so you have to
 * provide something that can be.
 *
 * Returns pointer to the beginning of the string (the pointer may have
 * changed due to reallocation).
 */

char *
mp_printf_append(struct mempool *mp, char *ptr, const char *fmt, ...)
_format_check(printf,3,4);

/*
 * Like @mp_printf_append(), but uses `va_list` for parameters.
 */
char *
mp_vprintf_append(struct mempool *mp, char *ptr, const char *fmt, va_list args);

#endif
