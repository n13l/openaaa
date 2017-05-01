#ifndef HASH_GENERIC_H__
#define HASH_GENERIC_H__

#include <sys/compiler.h>
#include <sys/cpu.h>
#include <list.h>
#include <math.h>
#include <limits.h>

#define HASH_RATIO_PRIME_32 0x9e370001UL
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

#ifdef CONFIG_DEBUG_HASH_TABLE
#define hash_first(hook) 
#define hash_next(hook)
#else
#define hash_first(hook)
#define hash_next(hook)
#endif/*CONFIG_DEBUG_HASH_TABLE*/

/* Decent compiler is able to make an obviously build-time decisions */
#define hash_bits(name) (unsigned int)(log2(array_size(name)))
#define hash_data(name, key) (u32)hash_u32(key, hash_bits(name))
#define hash_data_shared(key, bts) (u32)hash_u32(key, bits)

/* Type-generic macro used for hash calculation */

#define hash_init(table) \
	for (unsigned __i = 0; __i < array_size(table); __i++) \
		INIT_HLIST_PTR(&table[__i]);

#define hash_init_shared(table, shift) \
	for (unsigned __i = 0; __i < (1 << shift); __i++) \
		INIT_HLIST_PTR(&table[__i]);


#define hash_add(htable, hnode, slot) \
	hlist_add_head(& htable[slot], hnode)

#define hash_del(node) \
	hlist_del_init(node);

#define hash_get(table, key) \
	&name[hash_data(key, hash_bits(name))]

# define hlist_first(node)     ({ (list)->head; })
# define hlist_next(node, pos) ({node = pos->next; 1;})

#define hlist_entry(ptr, type, member) __container_of(ptr,type,member)

/*
#define hlist_for_each(pos, head) \
for (pos = (head)->first; pos ; pos = pos->next)

#define hlist_for_each_safe(pos, n, head) \
for (pos = (head)->first; pos && ({ n = pos->next; 1; }); \
pos = n)
*/

#define hlist_entry_safe(ptr, type, member) \
({ typeof(ptr) ____ptr = (ptr); ____ptr ? hlist_entry(____ptr, type, member) : NULL; })

#define hlist_for_each(node, list) \
	for (node = hlist_first(list); node; node = item->next)

#define hlist_for_each_delsafe(node, it, list) \
	for (node = hlist_first(list); it && ({it = pos->next; 1;}); node = it)

#define hlist_for_each_entry_safe(pos, n, list, member)                 \
	for (pos = hlist_entry_safe((list)->head, typeof(*pos), member);\
	     pos && ({ n = pos->member.next; 1; });                     \
	     pos = hlist_entry_safe(n, typeof(*pos), member))

#define hash_for_each_item_delsafe(htable, obj, tmp, member, slot)        \
	hlist_for_each_entry_safe(obj, tmp, &htable[slot], member)

#endif
