#include <sys/compiler.h>
#include <sys/log.h>
#include <mem/alloc.h>
#include <mem/pool.h>
#include <list.h>
#include <dict.h>

int
dict_unpack(struct dict *dict, char *buf, int len)
{
	char *ptr = buf, *end = buf + len, *a, *b;
	while (buf < end) {
		byte *key = buf;
		while (buf < end && *buf != ':' && *buf != '\n')
			buf++;
		if (buf >= end)
			return -1;
		if (*buf != ':')
			return buf - ptr;
		a = buf;
		*buf++ = 0;
		byte *value = buf;
		while (buf < end && *buf != '\n')
			buf++;
		if (buf >= end)
			return -1;
		b = buf;
		*buf++ = 0;

		dict_set_nf(dict, key, value);
		*a = ':';
		*b = '\n';

	}
	*buf++ = 0;
	return len;
}

static inline int
do_attr_enc(byte *buf, int len, int maxlen, const char *key, const char *val)
{
	if (len < 0)
		return len;
	int klen = strlen(key), vlen = strlen(val);
	int llen = klen + 1 + vlen + 1;
	if (len + llen > maxlen)
		return -1;

	buf += len; 
	memcpy(buf, key, klen); buf += klen;
	*buf++ = ':'; 
	memcpy(buf, val, vlen); buf += vlen; *buf = '\n';
	return llen;
}

int
dict_pack(struct dict *dict, char *buf, int size)
{
	int rv, len = 0;
	dict_for_each(a, dict->list) {
		rv = do_attr_enc(buf, len, size, a->key, a->val);
		if (rv < 1)
			return -EINVAL;
		len += rv;
		if (len > size)
			return -EINVAL;
	}

	return len;
}
