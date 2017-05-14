#include <sys/compiler.h>
#include <sys/cpu.h>
#include <sys/time.h>

#include <mem/alloc.h>
#include <mem/page.h>
#include <mem/map.h>

#include <aaa/lib.h>
#include <aaa/prv.h>

#include <buffer.h>
#include <list.h>
#include <hash.h>

#define HTABLE_BITS 9

DEFINE_HASHTABLE_SHARED(htable_sid);
DEFINE_HASHTABLE_SHARED(htable_bid);
DEFINE_HASHTABLE_SHARED(htable_uid);

struct attrs {
	char sid[128];
	char uid[32];
};

struct cursor {
	timestamp_t now;
	int expires; 
	struct bb id;
	u32 hash;
	u32 slot;
};

static timestamp_t
get_time(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv.tv_sec;
}

static inline void
acct_cursor(struct cursor *cursor, struct bb *id, int expires)
{
	cursor->hash = hash_buffer(id->addr, id->len);
	cursor->slot = hash_u32(cursor->hash, HTABLE_BITS);
	cursor->expires = expires;
	memcpy(&cursor->id, id, sizeof(*id));
	cursor->now = get_time();
}

struct session {
	struct page page;
	struct hnode sid;
	struct hnode uid;
	struct hnode bid;
        timestamp_t created;
        timestamp_t modified;
        timestamp_t expires;
	struct attrs attrs;
	unsigned char obj[];
};

struct request {
	struct bb sid;
	struct bb uid;
	struct bb bid;
	u32  hash_sid;
	u32  hash_uid;
	u32  hash_bid;
};

static struct pagemap *pagemap = NULL;

u32 htab_pages;
u32 shift = 12, pages = 32768;

int
acct_init(void)
{
	htab_pages = align_to(CPU_PAGE_SIZE, (1<<HTABLE_BITS) * sizeof(struct hlist));
	htable_sid = mmap_open(NULL, MAP_SHARED | MAP_ANON, shift, htab_pages);
	if (!htable_sid)
		die("mm_open() failed reason=%s", strerror(errno));

	hash_init_shared(htable_sid, shift);

	debug3("mm area=%p shift=%d pages=%d table %d MB", htable_sid, 
		HTABLE_BITS, htab_pages, (int)pages2mb(HTABLE_BITS, htab_pages));
	
	pagemap = mmap_open(NULL, MAP_SHARED | MAP_ANON, shift, pages);
	if (!pagemap)
		die("mm_open() failed reason=%s", strerror(errno));

	debug3("mm area=%p shift=%d pages=%d size=%lu MB(s)", 
		pagemap, shift, pages, pages2mb(shift, pages));

	return 0;
}

int
acct_fini(void)
{
	if (pagemap)
		mmap_close(pagemap);
	return 0;
}

int
page_lock(struct page *page)
{
	return 0;
}

int
page_trylock(struct page *page)
{
	return 0;
}

int
page_unlock(struct page *page)
{
	return 0;
}

int
page_copy(struct page *page, struct page *from)
{
	page_lock(page);
	memcpy(page, from, 1 << shift);
	page_unlock(page);
	return 0;
}

static int 
session_parse(struct aaa *aaa, byte *buf, unsigned int len)
{
	len--; /* zero ending */
	byte *ptr = buf, *end = buf + len, *a, *b;
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
                
                struct attr *attr = dict_lookup(&aaa->attrs, key, 0);
                if (attr && (attr->flags & ATTR_CHANGED)) {
                        debug2("%s:%s changed", attr->key, attr->val);
                } else {
		        debug2("%s:%s", key, value);
                        dict_set_nf(&aaa->attrs, key, value);
                }
		*a = ':';
		*b = '\n';

	}
	*buf++ = 0;
	return len;
}


int
session_read(struct aaa *aaa, struct session *session)
{
	return session_parse(aaa, session->obj, (1<<shift) - sizeof(*session));
}

static int
attr_enc(byte *buf, int len, int maxlen, const char *key, const char *val)
{
	if (len < 0)
		return len;

	int klen = strlen(key), vlen = strlen(val);
	int linelen = klen + 1 + vlen + 1;

	if (len + linelen > maxlen)
		return -1;
	buf += len;
	memcpy(buf, key, klen);
	buf += klen;
	*buf++ = ':';
	memcpy(buf, val, vlen);
	buf += vlen;
	*buf = '\n';
	return linelen;
}

static inline int
session_build(struct aaa *aaa, byte *buf, int size)
{
	int len = 0;
	dict_for_each(a, aaa->attrs.list) {
		len += attr_enc(buf, len, size, a->key, a->val);
		debug2("%s:%s", a->key, a->val);
		if (len > size)
			return -EINVAL;
	}

	return len;
}

static int
session_write(struct aaa *aaa, struct session *session)
{
	return session_build(aaa, session->obj, (1<<shift) - sizeof(*session));
}

static void
expired(struct session *session)
{
	debug2("session id=%s expired.", session->attrs.sid);
	hash_del(&session->sid);
	page_free(pagemap, (struct page *)session);
}

static int
lookup(struct aaa *aaa, struct cursor *sid)
{
	struct session *session = NULL;
	struct hnode *it = NULL;
	int rv = -1;
	hash_for_each_item_delsafe(htable_sid, session, it, sid, sid->slot) {
		int exp = session->expires - sid->now;
		if (exp < 1) {
			expired(session);
			continue;
		}

		if (rv == 0)
			continue;

		if (strcmp(sid->id.addr, session->attrs.sid))
			continue;

		debug2("session id=%s attached.", session->attrs.sid);
		session_read(aaa, session);
		rv = 0;
	}

	return rv;
}

static void
set_id(struct session *session, struct cursor *id)
{
	strncpy(session->attrs.sid, id->id.addr, sizeof(session->attrs.sid)-1);
}

static int
create(struct aaa *aaa, struct cursor *sid)
{
	struct page *page = NULL;
	if (!(page = page_alloc_safe(pagemap)))
		goto cleanup;

	struct session *session = (struct session *)page;
	session->created = session->modified = sid->now;
	session->expires = session->created + sid->expires;

	set_id(session, sid);
	aaa_attr_set(aaa, "sess.id", (char *)sid->id.addr);
	aaa_attr_set(aaa, "sess.created",  printfa("%jd", (intmax_t)session->created));
	aaa_attr_set(aaa, "sess.modified", printfa("%jd", (intmax_t)session->modified));
	aaa_attr_set(aaa, "sess.expires",  printfa("%jd", (intmax_t)session->expires));

	if (session_write(aaa, session) < 0)
		goto cleanup;
	hash_add(htable_sid, &session->sid, sid->slot);

	debug2("session id=%s created.", session->attrs.sid);
	return 0;
cleanup:
	if (page)
		page_free(pagemap, page);
	return -EINVAL;
}

int
session_bind(struct aaa *aaa, const char *id)
{
	struct cursor csid;
	struct bb sid = { .addr = (void *)id, .len = strlen(id) };
	acct_cursor(&csid, &sid, AAA_SESSION_EXPIRES);

        debug2("id=%s hash=%d slot=%d", sid.addr, csid.hash, csid.slot);

	if (!(lookup(aaa, &csid)))
		return 0;
	if (!(create(aaa, &csid)))
		return 0;

	return -EINVAL;
}

int
session_select(struct aaa *aaa, const char *id)
{
	return -EINVAL;
}

static int
commit(struct aaa *aaa, struct cursor *sid)
{
	struct session *session = NULL;
	struct hnode *it = NULL;
	int rv = -1;
	hash_for_each_item_delsafe(htable_sid, session, it, sid, sid->slot) {
		int exp = session->expires - sid->now;
                debug4("sess id=%s expires in %d sec(s)", session->attrs.sid, exp);
		if (exp < 1) {
			expired(session);
			continue;
		}

		if (rv == 0)
			continue;
		if (strcmp(sid->id.addr, session->attrs.sid))
			continue;

                const char *modified = aaa_attr_get(aaa, "sess.modified");
                const char *expires  = aaa_attr_get(aaa, "sess.expires");

                if (!modified || !expires)
                        continue;

		session->modified = strtol(modified, NULL, 10);
		session->expires  = strtol(expires, NULL, 10);

		session_write(aaa, session);
		debug2("session id=%s commited.", session->attrs.sid);
		rv = 0;
	}

	return rv;
}

int
session_commit(struct aaa *aaa, const char *id)
{
	struct cursor csid;
	struct bb sid = { .addr = (void *)id, .len = strlen(id) };
	acct_cursor(&csid, &sid, AAA_SESSION_EXPIRES);

        debug2("id=%s hash=%d slot=%d", sid.addr, csid.hash, csid.slot);

        if (lookup(aaa, &csid))
		return -EINVAL;

	return commit(aaa, &csid);
}

int
session_touch(struct aaa *aaa, const char *id)
{
	struct cursor csid;
	struct bb sid = { .addr = (void *)id, .len = strlen(id) };
	acct_cursor(&csid, &sid, AAA_SESSION_EXPIRES);

        debug2("id=%s hash=%d slot=%d", sid.addr, csid.hash, csid.slot);
        if (lookup(aaa, &csid))
		return -EINVAL;

	return commit(aaa, &csid);
}
