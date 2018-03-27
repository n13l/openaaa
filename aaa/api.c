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
	struct aaa *aaa = mm_pool_zalloc(mp, sizeof(*aaa));

	aaa->mp = mp;
	aaa->mp_attrs = mm_pool_create(CPU_PAGE_SIZE, 0);
	aaa->attrs_it = NULL;
	aaa->timeout = AAA_SESSION_EXPIRES;

	dict_init(&aaa->attrs, mm_pool(aaa->mp_attrs));
	return aaa;
}

void
aaa_free(struct aaa *aaa)
{
	mm_pool_destroy(aaa->mp_attrs);
	mm_pool_destroy(aaa->mp);
}

void
aaa_set_timeout(struct aaa *aaa, int timeout)
{
	aaa->timeout = timeout;
}

int
aaa_bind(struct aaa *aaa)
{
	const char *sid = aaa_attr_get(aaa, "sess.id");
	if (!sid || !*sid)
		return -EINVAL;

	aaa->sid = sid;
	return udp_bind(aaa);
}

void
aaa_reset(struct aaa *aaa)
{
	mm_pool_flush(aaa->mp_attrs);
	dict_init(&aaa->attrs, mm_pool(aaa->mp_attrs));
	aaa->attrs_it = NULL;
}

int
aaa_attr_set(struct aaa *aaa, const char *attr, const char *value)
{
	if (!attr || !value)
		return -EINVAL;

	dict_set(&aaa->attrs, attr, value);
	return 0;
}

const char *
aaa_attr_get(struct aaa *aaa, const char *attr)
{
	return attr ? dict_get(&aaa->attrs, attr): NULL;
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
aaa_attr_first(struct aaa *aaa, const char *path)
{
	struct list *list = &aaa->attrs.list;
	struct node *node = list_first(list);

	aaa->attrs_it = NULL;
	if (!node)
		return NULL;

	struct attr *attr = __container_of(node, struct attr, node);
	if (!attr->key)
		return NULL;

	aaa->attrs_it = node;
	return attr->key;
}

const char *
aaa_attr_next(struct aaa *aaa)
{
	struct list *list = &aaa->attrs.list;
	struct node *node = list_next(list, aaa->attrs_it);

	if (!node)
		return NULL;

	struct attr *attr = __container_of(node, struct attr, node);
	if (!attr->key)
		return NULL;

	aaa->attrs_it = node;
	return attr->key;
}

void
aaa_attr_dump(struct aaa *aaa, const char *path)
{
	struct list *list = &aaa->attrs.list;
	struct node *node;

	for (node = list_first(list); node; node = list_next(list, node)) {
		struct attr *attr = __container_of(node, struct attr, node);
		debug("%s:%s", attr->key, attr->val);
	}
}

int
aaa_select(struct aaa *aaa, const char *path)
{
	return -1;
}

static timestamp_t
get_time(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv.tv_sec;
}

int
aaa_touch(struct aaa *aaa)
{
	const char *sid = aaa_attr_get(aaa, "sess.id");
	if (!sid || !*sid)
		return -EINVAL;

        timestamp_t modified = get_time();
        timestamp_t expires  = modified + aaa->timeout;
	
	aaa_attr_set(aaa, "sess.modified", printfa("%jd", (intmax_t)modified));
	aaa_attr_set(aaa, "sess.expires",  printfa("%jd", (intmax_t)expires));

	return 0;
}

int
aaa_commit(struct aaa *aaa)
{
	const char *sid = aaa_attr_get(aaa, "sess.id");
	if (!sid || !*sid)
		return -EINVAL;

	aaa->sid = sid;
	dict_sort(&aaa->attrs);
	return udp_commit(aaa);
}
