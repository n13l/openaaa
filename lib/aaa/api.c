#include <sys/compiler.h>
#include <sys/cpu.h>
#include <sys/log.h>
#include <mem/pool.h>
#include <aaa/lib.h>
#include <aaa/prv.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

struct aaa *
aaa_new(enum aaa_endpoint type)
{
	struct mempool *mp = mp_new(CPU_PAGE_SIZE);
	struct aaa *c = mp_alloc(mp, sizeof(*c));

	c->mp = mp;

	aaa_config_load(c);

	return c;
}

void
aaa_free(struct aaa *aaa)
{
	mp_delete(aaa->mp);
}

int
aaa_bind(struct aaa *aaa, int type, const char *value)
{
	return -1;
}

int
aaa_attr_set(struct aaa *aaa, const char *attr, char *value)
{
	return -1;
}

const char *
aaa_attr_get(struct aaa *aaa, const char *attr)
{
	return NULL;
}

int
aaa_attr_del_value(struct aaa *aaa, const char *key, const char *val)
{
	return -1;
}

int
aaa_attr_has_value(struct aaa *aaa, const char *key, const char *val)
{
	return -1;
}

const char *
aaa_attr_find_first(struct aaa *aaa, const char *path, unsigned recurse)
{
	return NULL;
}

const char *
aaa_attr_find_next(struct aaa *aaa)
{
	return NULL;
}

int
aaa_select(struct aaa *aaa, const char *path)
{
	return -1;
}

int
aaa_touch(struct aaa *aaa)
{
	return -1;
}

int
aaa_commit(struct aaa *aaa)
{
	return -1;
}
