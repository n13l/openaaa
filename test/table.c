/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2013 Daniel Kubec <niel@rtfm.cz>
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

#include <sys/compiler.h>
#include <sys/cpu.h>
#include <mem/alloc.h>
#include <mem/cache.h>
#include <mem/page.h>
#include <posix/list.h>
#include <posix/hash.h>

DECLARE_HASHTABLE(person_name, 9);
DECLARE_HASHTABLE(person_age,  9);

struct person {
	char *name;
	unsigned int age;
	struct hnode node_name;
	struct hnode node_age;
};

static struct person *
person(struct mm_pool *mp, char *name, unsigned int age)
{
	struct person *person = mm_alloc(mp, sizeof(*person));

	person->name = mm_strdup(mp, name);
	person->age  = age;

	hnode_init(&person->node_name);
	hnode_init(&person->node_age);
	return person;
}

int
main(void)
{
	struct mm_pool *mp = mm_create(MM_POOL, CPU_PAGE_SIZE, MM_FAST_ALIGN);

	hash_init(person_name);
	hash_init(person_age);

	_unused struct person *myself = person(mp, "Daniel", 15);

	_unused u32 hash1 = hash_data(person_name, "daniel");
	_unused u32 hash2 = hash_data(person_age, 15);

	debug("hash data=%u", (unsigned int)hash1);

	/*
	for (int i = 0; i < 10; i++) {
		_unused struct person *person = person(mp, "Daniel", 1979);
		hash_add(htable, (u32)person->id, key);
	}

	// hash_for_each(object, name, "Daniel);
*/
	/*
	hash_for_each(person_name, person, n_name, "Daniel") {
		struct person *it = __container_of(node, n_name);
	}
*/
	//hash_for_each_slot()
	//hash_for_each_object()

	mm_destroy(mp);
	return 0;
}
