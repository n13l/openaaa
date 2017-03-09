/*
 * The MIT License (MIT)      
 *
 * Copyright (c) 2015 Daniel Kubec <niel@rtfm.cz> 
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
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,ARISING FROM, 
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN    
 * THE SOFTWARE.
 */

#ifndef HASH_GENERIC_H__
#define HASH_GENERIC_H__

#include <sys/compiler.h>
#include <sys/cpu.h>
#include <list.h>
#include <math.h>
#include <limits.h>

/*
 * Knuth recommends primes in approximately HASH ratio to the maximum
 * integer representable by a machine word for multiplicative hashing.
 * Chuck Lever verified the effectiveness of this technique:
 * http://www.citi.umich.edu/techreports/reports/citi-tr-00-1.pdf
 *
 * These primes are chosen to be bit-sparse, that is operations on
 * them can use shifts and additions instead of multiplications for
 * machines where multiplications are slow.
 */

/* 2^31 + 2^29 - 2^25 + 2^22 - 2^19 - 2^16 + 1 */
#define HASH_RATIO_PRIME_32 0x9e370001UL
/*  2^63 + 2^61 - 2^57 + 2^54 - 2^51 - 2^18 + 1 */
#define HASH_RATIO_PRIME_64 0x9e37fffffffc0001UL
#if CPU_ARCH_BITS == 32
#define HASH_RATIO_PRIME HASH_RATIO_PRIME_32
#define hash_long(val, bits) hash_u32((u32)val, bits)
#elif CPU_ARCH_BITS == 64
#define hash_long(val, bits) hash_u64((u64)val, bits)
#define HASH_RATIO_PRIME HASH_RATIO_PRIME_64
#else
#error not supported architecture
#endif

static inline u64
hash_u64(u64 val, unsigned int bits)
{
	u64 hash = val;
	u64 n = hash; n <<= 18;
	hash -= n; n <<= 33;
	hash -= n; n <<= 3;
	hash += n; n <<= 3; 
	hash -= n; n <<= 4;
	hash += n; n <<= 2;
	hash += n;
	return hash >> (64 - bits);
}

static inline u32
hash_u32(u32 val, unsigned int bits)
{
	u32 hash = val * HASH_RATIO_PRIME_32;
	return hash >> (32 - bits);
}

static inline unsigned long
hash_ptr(const void *ptr, unsigned int bits)
{
	return (unsigned long)hash_long(ptr, bits);
}

static inline unsigned long
hash_string(const char *str)
{
	unsigned long v = 0;
	for (const char *c = str; *c; )
		v = (((v << 1) + (v >> 14)) ^ (*c++)) & 0x3fff;
	return(v);
}

#define DEFINE_HASHTABLE(name, bits) \
	struct hlist name[1 << (bits)]

#ifdef CONFIG_DEBUG_HASH_TABLE
#define hash_first(hook) 
#define hash_next(hook)
#else
#define hash_first(hook)
#define hash_next(hook)
#endif/*CONFIG_DEBUG_HASH_TABLE*/

/* Decent compiler is able to make an obviously build-time decisions */
#define hash_bits(name) (log2(array_size(name)))
/* Type-generic macro used for hash calculation */
#define hash_data(name, key) __extension__ \
({ \
	u32 _H = (u32)__builtin_choose_expr( \
	         __builtin_types_compatible_p(__typeof__(key), u32),  \
	           hash_u32((u32)(uintptr_t)key, hash_bits(name)), \
	         __builtin_choose_expr( \
	         __builtin_types_compatible_p(__typeof__(key), u64),  \
	           hash_u64((u64)(uintptr_t)key, hash_bits(name)), \
	         __builtin_choose_expr( \
	         __builtin_types_compatible_p(__typeof__(key), char []), \
	           hash_u32((u32)hash_string((const char *)key), \
			                      hash_bits(name)), \
	         __builtin_choose_expr( \
	         __builtin_types_compatible_p(__typeof__(key), const char[]),\
	           hash_u32((u32)hash_string((const char*)key), \
			                     hash_bits(name)), \
	        (u32)0))));\
 	_H; \
}) 

#define hash_init(table) \
	for (unsigned __i = 0; __i < array_size(table); __i++) \
		INIT_HLIST_PTR(&table[__i]);

#define hash_add(table, node, key) \
	hlist_add_head(node, &table[hash_data(key, hash_bits(table))])

#define hash_del(table, node) \
	hlist_del_init(node);

#define hash_get(table, key) \
	&name[hash_data(key, hash_bits(name))]

/*
#ifdef CONFIG_DEBUG_LIST
#ifndef hlist_next_hook(pos)
#define hlist_next_hook(pos)
#endif
# define hlist_first(node)     ({ (list)->head; )}
# define hlist_next(node, pos) ({node = node->next; hlist_next_hook(pos) 1;})
#else
# define hlist_first(node)     ({ (list)->head; })
# define hlist_next(node, pos) ({node = pos->next; 1;})
#endif

#define hlist_for_each(node, list) \
	for (node = hlist_first(list); node; node = item->next)

#define hlist_for_each_safe(node, it, list) \
	for (node = hlist_first(list); it && ({it = pos->next; 1;}); node = it)

#define hlist_walk(node, list)
#define hlist_walk_safe(node, it, list)

#define hash_for_each(name, obj, member, key)
#define hash_for_each_safe(name, obj, it, member, key)
*/
#define hash_for_each(name, obj, member, key) \
	hlist_for_each(obj, &name[hash_data(key, hash_bits(name))],member)

#define hash_for_each_delsafe(name, obj, it, member, key)	\
	hlist_for_each_delsafe(obj, it, \
	                    &name[hash_data(key, hash_bits(name))], member)

#define slot_for_each(table)
#define slot_for_each_delsafe()

#endif
