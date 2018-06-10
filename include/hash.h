#ifndef __HASH_GENERIC_H__
#define __HASH_GENERIC_H__

#include <sys/compiler.h>
#include <sys/cpu.h>
#include <math.h>
#include <limits.h>

#if CPU_ARCH_BITS == 32
#define hash_long(val, bits) hash_u32((u32)val, bits)
#elif CPU_ARCH_BITS == 64
#define hash_long(val, bits) hash_u64((u64)val, bits)
#endif

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

static inline unsigned long
hash_buffer(const char *ptr, int size)
{
	unsigned long v = 0;
	for (const char *c = ptr; size; size--)
		v = (((v << 1) + (v >> 14)) ^ (*c++)) & 0x3fff;
	return(v);
}

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
		INIT_HLIST_PTR(&table[__i]);

#define hash_init_shared(table, shift) \
	for (unsigned __i = 0; __i < (1 << shift); __i++) \
		INIT_HLIST_PTR(&table[__i]);

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
