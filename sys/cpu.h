/*
 * The MIT License (MIT)         Copyright (c) 2015 Daniel Kubec <niel@rtfm.cz>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"),to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef __SYS_CPU_H__
#define __SYS_CPU_H__

/* Hardware-accelerated implementation of CRC-32C (Castagnoli) */
#define CPU_CAP_CRYPTO_CRC32C             1

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

#ifndef CPU_SIMD_ALIGN
#define CPU_SIMD_ALIGN 16
#endif

#define CPU_ADDR_ALIGN CPU_ARCH_BITS

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

const char *
cpu_vendor(void);

int
cpu_has_cap(int capability);

int
cpu_has_crc32c(void);

void
cpu_dump_extension(void);

#endif/*__CPU_H__*/
