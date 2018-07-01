/*
 * Generic hash functions 
 *
 * The MIT License (MIT)         
 *
 * Copyright (c) 2013 - 2019                        Daniel Kubec <niel@rtfm.cz>
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
 **/

#ifndef __HASH_GENERIC_H__
#define __HASH_GENERIC_H__

#include <sys/compiler.h>
#include <sys/cpu.h>
#include <math.h>
#include <limits.h>

#define XXH_INLINE_ALL
#include "xxhash.h"

static inline u64
hash_u64(u64 x, unsigned int bits)
{
	x = (x ^ (x >> 30)) * (u64)(0xbf58476d1ce4e5b9);
	x = (x ^ (x >> 27)) * (u64)(0x94d049bb133111eb);
	x = x ^ (x >> 31);
	return x >> (64 - bits);
}

static inline u32
hash_u32(u32 x, unsigned int bits) 
{
	x = ((x >> 16) ^ x) * 0x45d9f3b;
	x = ((x >> 16) ^ x) * 0x45d9f3b;
	x = (x >> 16) ^ x;
	return x >> (32 - bits);
}

/*
 * http://www.burtleburtle.net/bob/hash/doobs.html
 *
 * Bernstein's hash
 *
 * If your keys are lowercase English words, this will fit 6 characters into a 
 * 32-bit hash with no collisions (you'd have to compare all 32 bits). If your 
 * keys are mixed case English words, 65*hash+key[i] fits 5 characters into a 
 * 32-bit hash with no collisions. That means this type of hash can produce 
 * (for the right type of keys) fewer collisions than a hash that gives a more 
 * truly random distribution. If your platform doesn't have fast multiplies, 
 * no sweat, 33*hash = hash+(hash<<5) and most compilers will figure that out 
 * for you.
 *
 * On the down side, if you don't have short text keys, this hash has a easily 
 * detectable flaws. For example, there's a 3-into-2 funnel that 0x0021 and 
 * 0x0100 both have the same hash (hex 0x21, decimal 33)
 */

static inline u32
hash_u32_bernstein(u8 *key, u32 len, u32 level)
{
	u32 i, hash = level;
	for (i = 0; i < len; ++i) hash = 33 * hash + key[i];
		return hash;
}

static inline unsigned long
hash_ptr(const void *ptr, unsigned int bits)
{
#if CPU_ARCH_BITS == 32
	return (unsigned long)hash_u32((u32)ptr, bits);
#elif CPU_ARCH_BITS == 64
	return (unsigned long)hash_u64((u64)ptr, bits);
#endif
}

static inline unsigned long
hash_string(const char *str)
{
	unsigned long v = 0;
	for (const char *c = str; *c; )
		v = (((v << 1) + (v >> 14)) ^ (*c++)) & 0x3fff;
	return(v);
}

static inline unsigned long
hash_buffer(const char *ptr, int size)
{
	unsigned long v = 0;
	for (const char *c = ptr; size; size--)
		v = (((v << 1) + (v >> 14)) ^ (*c++)) & 0x3fff;
	return(v);
}

/* 
 * https://arxiv.org/abs/1503.03465
 * Faster 64-bit universal hashing using carry-less multiplications
 *
 * Daniel Lemire, Owen Kaser
 * (Submitted on 11 Mar 2015 (v1), last revised 4 Nov 2015 (this version, v8))
 * Intel and AMD support the Carry-less Multiplication (CLMUL) instruction set 
 * in their x64 processors. We use CLMUL to implement an almost universal 
 * 64-bit hash family (CLHASH). We compare this new family with what might be 
 * the fastest almost universal family on x64 processors (VHASH). We find that 
 * CLHASH is at least 60% faster. We also compare CLHASH with a popular hash 
 * function designed for speed (Google's CityHash). We find that CLHASH is 40% 
 * faster than CityHash on inputs larger than 64 bytes and just as fast 
 * otherwise.
 */

#define DEFINE_HASHTABLE(name, bits) struct hlist name[1 << (bits)]
#define DEFINE_HASHTABLE_SHARED(name) struct hlist *name

#define hash_bits(name) (unsigned int)(log2(array_size(name)))
#define hash_entries(name) array_size(name)
#define hash_data(name, key) (u32)hash_u32(key, hash_bits(name))
#define hash_data_shared(key, bts) (u32)hash_u32(key, bits)
#define hash_skey(name, key) \
	(u32)hash_u32(hash_string(key), hash_bits(name))
#define hash_sbuf(name, key, len) \
	(u32)hash_u32(hash_buffer(key, len), hash_bits(name))

#define hash_init(table) \
	for (unsigned __i = 0; __i < array_size(table); __i++) \
		table[__i] = HLIST_INIT;

#define hash_init_shared(table, shift) \
	for (unsigned __i = 0; __i < (1 << shift); __i++) \
		table[__i] = HLIST_INIT;

#define hash_add(htable, hnode, slot) hlist_add(&htable[slot],hnode)

#define hash_del(node) hlist_del(node);
#define hash_get(table, key) &name[hash_data(key, hash_bits(name))]

#define hash_for_each(__table, __it, __key) \
	hlist_for_each(&__table[__key], __it)

#define hash_for_each_delsafe(__table, __it, __key) \
	hlist_for_each_delsafe(&__table[__key], __it)

#define hash_walk_delsafe(list, ...) \
	va_dispatch(hash_walk_delsafe,__VA_ARGS__)(list,__VA_ARGS__)
#define hash_walk_delsafe3(htable,slot,it,member) \
	hlist_walk_delsafe(&htable[slot],it,member)

#endif
