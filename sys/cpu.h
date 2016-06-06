#ifndef __SYS_CPU_H__
#define __SYS_CPU_H__

/*
 * 32 bytes appears to be the most common cache line size,
 * so make that the default here. Architectures with larger
 * cache lines need to provide their own define.
 */

#ifdef CONFIG_X86_L1_CACHE_SHIFT
# define L1_CACHE_SHIFT CONFIG_X86_L1_CACHE_SHIFT
#endif

#ifndef L1_CACHE_SHIFT
# define L1_CACHE_SHIFT  5
#endif

#define L1_CACHE_BYTES  (1 << L1_CACHE_SHIFT)
#ifndef L1_CACHE_STRIDE
# define L1_CACHE_STRIDE (4 * L1_CACHE_BYTES)
#endif

#define CPU_CACHE_STRIDE L1_CACHE_STRIDE
#define CPU_CACHE_LINE CPU_CACHE_STRIDE

#ifdef CONFIG_LITTLE_ENDIAN
#define CPU_LITTLE_ENDIAN y
#endif

#ifdef CONFIG_BIG_ENDIAN
#define CPU_BIG_ENDIAN y
#endif

#ifdef __x86_64
# ifndef CPU_ARCH
#  define CPU_ARCH            x86_64
# endif
# ifndef CPU_ARCH_BITS
#  define CPU_ARCH_BITS       64
# endif
# ifndef CPU_CHAR_BITS
#  define CPU_CHAR_BITS       8 
# endif
# ifndef CPU_ALLOW_UNALIGNED
#  define CPU_ALLOW_UNALIGNED 1
# endif
# ifndef CPU_LITTLE_ENDIAN
#  define CPU_LITTLE_ENDIAN   1
# endif
# ifndef CPU_STRUCT_ALIGN
#  define CPU_STRUCT_ALIGN    8 
# endif
# ifndef CPU_PAGE_SIZE
#  define CPU_PAGE_SIZE       4096
# endif
#else
# ifndef CPU_ARCH
#  define CPU_ARCH            x86
# endif
# ifndef CPU_ARCH_BITS
#  define CPU_ARCH_BITS       32
# endif
# ifndef CPU_CHAR_BITS
#  define CPU_CHAR_BITS       8
# endif
# ifndef CPU_ALLOW_UNALIGNED
#  define CPU_ALLOW_UNALIGNED 1
# endif
# ifndef CPU_STRUCT_ALIGN
#  define CPU_STRUCT_ALIGN    4
# endif
# ifndef CPU_PAGE_SIZE
#  define CPU_PAGE_SIZE       4096
# endif
#endif

#define for_each_online_cpu(cpu) 

#endif/*__CPU_H__*/
