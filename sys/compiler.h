#ifndef __SYS_COMPILER_H__
#define __SYS_COMPILER_H__

#include <stddef.h>
#include <stdint.h>
#include <limits.h>
#include <assert.h>

typedef uint8_t      byte;            /* Exactly 8 bits, unsigned            */
typedef uint8_t      u8;              /* Exactly 8 bits, unsigned            */
typedef int8_t       s8;              /* Exactly 8 bits, signed              */
typedef uint16_t     u16;             /* Exactly 16 bits, unsigned           */
typedef int16_t      s16;             /* Exactly 16 bits, signed             */
typedef uint32_t     u32;             /* Exactly 32 bits, unsigned           */
typedef int32_t      s32;             /* Exactly 32 bits, signed             */
typedef uint64_t     u64;             /* Exactly 64 bits, unsigned           */
typedef int64_t      s64;             /* Exactly 64 bits, signed             */
typedef unsigned int uint;            /* Shorter type for unsigned int       */
typedef u64          timestamp_t;     /* Milliseconds since an unknown epoch */

#ifdef __CHECKER__
#define __bitwise __attribute__((bitwise))
#else
#define __bitwise
#endif
#ifdef __CHECK_ENDIAN__
#define endian_bitwise __bitwise
#else
#define endian_bitwise
#endif

typedef u16 endian_bitwise le16;
typedef u16 endian_bitwise be16;
typedef u32 endian_bitwise le32;
typedef u32 endian_bitwise be32;
typedef u64 endian_bitwise le64;
typedef u64 endian_bitwise be64;

typedef s16 endian_bitwise sl16;
typedef s16 endian_bitwise sb16;
typedef s32 endian_bitwise sl32;
typedef s32 endian_bitwise sb32;
typedef s64 endian_bitwise sl64;
typedef s64 endian_bitwise sb64;

typedef u16 endian_bitwise ul16;
typedef u16 endian_bitwise ub16;
typedef u32 endian_bitwise ul32;
typedef u32 endian_bitwise ub32;
typedef u64 endian_bitwise ul64;
typedef u64 endian_bitwise ub64;

typedef u16 endian_bitwise sum16;
typedef u32 endian_bitwise wsum;

#if __GNUC__ >= 3
# undef  inline
# define inline         inline __attribute__ ((always_inline))
# define _noinline     __attribute__ ((noinline))
# define _pure         __attribute__ ((pure))
# define _const        __attribute__ ((const))
# define _noreturn     __attribute__ ((noreturn))
# define _malloc       __attribute__ ((malloc))
# define _must_check   __attribute__ ((warn_unused_result))
# define _deprecated   __attribute__ ((deprecated))
# define _used         __attribute__ ((used))
# define _unused       __attribute__ ((unused))
# define _packed       __attribute__ ((packed))
# define _align(x)     __attribute__ ((aligned (x)))
# define _align_max    __attribute__ ((aligned))
# define _sentinel     __attribute__ ((sentinel))
# define _format_check(x,y,z) __attribute__((format(x,y,z)))

/* Call function upon start of program */
#define _constructor __attribute__((constructor))
/** Define constructor with a given priority **/
#define _constructor_with_priority(p) __attribute__((constructor(p)))

/* branch prediction */ 
#define likely(x)      __builtin_expect (!!(x), 1)
#define unlikely(x)    __builtin_expect (!!(x), 0)

#define bswap16(x)     __builtin_bswap16(x)
#define bswap32(x)     __builtin_bswap32(x)
#define bswap64(x)     __builtin_bswap64(x)

#define _atomic_xadd(P, V) __sync_fetch_and_add((P), (V))
#define _cmpxchg(P, O, N) __sync_val_compare_and_swap((P), (O), (N))
#define _atomic_inc(P) __sync_add_and_fetch((P), 1)
#define _atomic_dec(P) __sync_add_and_fetch((P), -1) 
#define _atomic_add(P, V) __sync_add_and_fetch((P), (V))
#define _atomic_set_bit(P, V) __sync_or_and_fetch((P), 1<<(V))
#define _atomic_clear_bit(P, V) __sync_and_and_fetch((P), ~(1<<(V)))

#else
# define _noinline     /* no noinline */
# define _pure         /* no pure */
# define _const        /* no const */
# define _noreturn     /* no noreturn */
# define _malloc       /* no malloc */
# define _must_check   /* no warn_unused_result */
# define _deprecated   /* no deprecated */
# define _used         /* no used */
# define _unused       /* no unused */
# define _packed       /* no packed */
# define _align(x)     /* no aligned */
# define _align_max    /* no align_max */
# define likely(x)      (x)
# define unlikely(x)    (x)
#endif

#ifndef min
#define min(a,b) (((a)<(b))?(a):(b))
#endif

#ifndef __max
#define __max(a,b) (((a)>(b))?(a):(b))
#endif

#define rol(x, bits) \
	(((x) << (bits)) | ((uint)(x) >> (sizeof(uint) * 8 - (bits)))) 
#define ror(x, bits) \
	(((uint)(x) >> (bits)) | ((x) << (sizeof(uint) * 8 - (bits))))

#ifndef array_size
#define array_size(a) (sizeof(a)/sizeof(*(a)))
#endif

#define do_stringify(x...)     #x
#define stringify(x...)       do_stringify(x)

/* Check that a pointer @x is of type @type. Fail compilation if not. **/
#define _check_ptr_type(x, type) ((x)-(type)(x) + (type)(x))             
/* Return OFFSETOF() in form of a pointer. **/
#define _ptr_to(s, i) &((s*)0)->i                                       
/* Offset of item @i from the start of structure @s */
#define _offsetof(s, i) ((uint)offsetof(s, i))                         
/* 
 * Given a pointer @p to item @i of structure @s, return a pointer to the start
 * of the struct. 
 */
#define skip_back(s, i, p) ((s *)((char *)p - _offsetof(s, i)))       
/*
 * Align an integer @s to the nearest higher multiple of @a (which should be
 * a power of two) 
 */
#define align_to(s, a) (((s)+a-1)&~(a-1))

#define align_struct(s) align_to(s, CPU_STRUCT_ALIGN)
#define align_page(s) align_to(s, CPU_PAGE_SIZE)
#define align_lock(s) align_to(s, L1_CACHE_BYTES)
#define align_simd(s) align_to(s, CPU_SIMD_ALIGN)
#define align_addr(s) align_to(s, sizeof(void *))

/** Align a pointer @p to the nearest higher multiple of @s. **/
#define align_ptr(p, s) ((uintptr_t)(p) % (s) ? \
	(typeof(p))((uintptr_t)(p) + (s) - (uintptr_t)(p) % (s)) : (p))

#define unaligned_part(ptr, type) (((uintptr_t) (ptr)) % sizeof(type))
#define aligned_part(size, align) (size & ~(size_t)(align - 1))

/*
 * Instruct the compiler to perform only a single access to a variable
 * (prohibits merging and refetching). The compiler is also forbidden to reorder
 * successive instances of __access_once(), but only when the compiler is aware
 * of particular ordering. Compiler ordering can be ensured, for example, by
 * putting two __access_once() in separate C statements.
 *
 * This macro does absolutely -nothing- to prevent the CPU from reordering,
 * merging, or refetching absolutely anything at any time.  Its main intended
 * use is to mediate communication between process-level code and irq/NMI
 * handlers, all running on the same CPU.
 */

#define __access_once(x) (*(__volatile__  __typeof__(x) *)&(x))
#define __is_signed_type(type) ((type) -1 < (type) 0)

/*
 * Sign-extend to long if needed, and output type is unsigned long.
 */
#define __cast_long_keep_sign(v) \
	(__is_signed_type(__typeof__(v)) ? \
	(unsigned long) (long) (v) : \
	(unsigned long) (v))

#define check_types_match(expr1, expr2)	\
	((typeof(expr1) *)0 != (typeof(expr2) *)0)

/*
 * __container_of - Get the address of an object containing a field.
 *
 * @ptr: pointer to the field.
 * @type: type of the object.
 * @member: name of the field within the object.
 */

#define __container_of(ptr, type, member) \
({ \
	(type *)((byte *)ptr - offsetof(type, member)); \
})

#define container_of(ptr, type, member) \
({ \
	(type *)((byte *)ptr - offsetof(type, member)); \
})


#define __container_of_safe(ptr, type, member) \
({ \
	typeof(ptr) ____ptr = (ptr); \
	____ptr ? __container_of(____ptr, type, member): NULL; \
})

#define container_cmp(fn, a, b, type, member) \
({ \
 	fn( \
	(type *)((byte *)a - offsetof(type, member)), \
	(type *)((byte *)b - offsetof(type, member)) \
	); \
})

#define __container_cmp(fn, a, b, type, member) \
({ \
 	fn( \
	(type *)((byte *)a - offsetof(type, member)), \
	(type *)((byte *)b - offsetof(type, member)) \
	); \
})

#if __STDC_VERSION__ >= 201112L
#define instance_of(X, T) \
	_Generic((X), T: 1, const T: 1, default: 0)
#define pointer_of(X, T) \
	_Generic((X), T*: 1, const T*: 1, default: 0)
#define array_of(X, T) \
	_Generic((X), const T[sizeof(X)]: 1, T[sizeof(X)]: 1, default: 0)
#define aryptr_of(X, T) \
	_Generic((X), T *: 1, const T*: 1, const T[sizeof(X)]: 1, \
	              T[sizeof(X)]: 1, default: 0)

#else

#define instance_of(X, T) \
	__builtin_types_compatible_p(typeof(X), T) || \
	__builtin_types_compatible_p(typeof(X), const T) ? 1 : 0

#define pointer_of(X, T) \
	__builtin_types_compatible_p(typeof(X), T*) || \
	__builtin_types_compatible_p(typeof(X), const T*) ? 1 : 0

#define array_of(X, T) \
	__builtin_types_compatible_p(typeof(X), T*) || \
	__builtin_types_compatible_p(typeof(X), const T*) ? 1 : 0

#define aryptr_of(X, T) \
	__builtin_types_compatible_p(typeof(X), T*)       || \
	__builtin_types_compatible_p(typeof(X), const T*) || \
	__builtin_types_compatible_p(typeof(X), T[sizeof(X)] )       || \
	__builtin_types_compatible_p(typeof(X), const T[sizeof(X)]) ? 1 : 0

#endif

/* workarround bug for old gcc gnu1x support */
#if __GNUC__ < 5
#undef instance_of
#undef pointer_of
#undef array_of
#undef aryptr_of

#define instance_of(X, T) \
	__builtin_types_compatible_p(typeof(X), T) || \
	__builtin_types_compatible_p(typeof(X), const T) ? 1 : 0

#define pointer_of(X, T) \
	__builtin_types_compatible_p(typeof(X), T*) || \
	__builtin_types_compatible_p(typeof(X), const T*) ? 1 : 0

#define array_of(X, T) \
	__builtin_types_compatible_p(typeof(X), T*) || \
	__builtin_types_compatible_p(typeof(X), const T*) ? 1 : 0

#define aryptr_of(X, T) \
	__builtin_types_compatible_p(typeof(X), T*)       || \
	__builtin_types_compatible_p(typeof(X), const T*) || \
	__builtin_types_compatible_p(typeof(X), T[sizeof(X)] )       || \
	__builtin_types_compatible_p(typeof(X), const T[sizeof(X)]) ? 1 : 0


#endif

#define if_pointer_of(X, T) if(pointer_of(X,T))

#define __build_bug_on(condition) ((void)sizeof(char[1 - 2*!!(condition)]))
#define __build_bug_on_zero(e) (sizeof(struct { int:-!!(e); }))
#define __build_bug_on_null(e) ((void *)sizeof(struct { int:-!!(e); }))

#define va_nargs(...) va_nargs_impl(__VA_ARGS__, 5,4,3,2,1)
#define va_nargs_impl(_1,_2,_3,_4,_5,N,...) N
#define va_nargs2(...) ((int)(sizeof((int[]){ __VA_ARGS__ })/sizeof(int)))

#define va_dispatch(func, ...) \
	va_dispatch_(func, va_nargs(__VA_ARGS__))
#define va_dispatch_(func, nargs) \
	va_dispatch__(func, nargs)
#define va_dispatch__(func, nargs) func ## nargs

#define vmax(...) va_dispatch(max, __VA_ARGS__)(__VA_ARGS__)
#define vmax1(a) a
#define vmax2(a,b) ((a)>(b)?(a):(b))
#define vmax3(a,b,c) max2(max2(a,b),c)

#define EXPORT_SYMBOL(sym) extern typeof(sym) sym

#ifndef O_NOATIME
#define O_NOATIME 0
#endif

/* IBM XL C/C++ */
#if defined(__IBMCPP__) || defined(__xlC__) || defined(__xlc__)
/* http://www-01.ibm.com/support/docview.wss?uid=swg27039015 */
#ifndef __IBM_MACRO_WITH_VA_ARGS
#error "requires support for variadic macro extensions."
#endif
#ifndef __IBM__TYPEOF__
#error "requires support for the __typeof__ or typeof keyword."
#endif

#ifdef KBUILD_STR
#undef KBUILD_STR
#endif
#define KBUILD_STR(s) #s
#endif

int
pid_read(const char *file);

int
pid_write(const char *file);

#endif
