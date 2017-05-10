#include <sys/compiler.h>
#include <sys/cpu.h>
#include <sys/log.h>
#include <mem/pool.h>

#include <aaa/lib.h>
#include <aaa/prv.h>

#include <list.h>
#include <dict.h>

static int aaa_initialized = 0;

int (*aaa_server)(int argc, char *argv[]) = NULL;

struct aaa *
aaa_new(enum aaa_endpoint type, int flags)
{
	if (!aaa_initialized) {
		aaa_env_init();
		aaa_initialized = 1;
	}

	struct mm_pool *mp = mm_pool_create(CPU_PAGE_SIZE, 0);
	struct aaa *aaa = mm_alloc(mp, sizeof(*aaa));

	aaa->mp = mp;
	aaa->mp_attrs = mm_pool_create(CPU_PAGE_SIZE, 0);

	dict_init(&aaa->attrs, aaa->mp_attrs);

	return aaa;
}

void
aaa_free(struct aaa *aaa)
{
	mm_pool_destroy(aaa->mp_attrs);
	mm_pool_destroy(aaa->mp);
}

int
aaa_bind(struct aaa *aaa)
{
	const char *sid = aaa_attr_get(aaa, "sess.id");
	if (!sid || !*sid)
		return -EINVAL;

	return udp_bind(aaa);
}

void
aaa_reset(struct aaa *aaa)
{
	mm_flush(aaa->mp_attrs);
	dict_init(&aaa->attrs, aaa->mp_attrs);
}

int
aaa_attr_set(struct aaa *aaa, const char *attr, const char *value)
{
	dict_set(&aaa->attrs, attr, value);
	return 0;
}

const char *
aaa_attr_get(struct aaa *aaa, const char *attr)
{
	return dict_get(&aaa->attrs, attr);
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
	return udp_commit(aaa);
}
