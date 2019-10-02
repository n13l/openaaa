#include <sys/compiler.h>
#include <sys/cpu.h>
#include <sys/time.h>
#include <list.h>
#include <mem/alloc.h>
#include <mem/page.h>
#include <mem/map.h>

#include <aaa/lib.h>
#include <aaa/prv.h>

#include <buffer.h>
#include <hash.h>

#define P_FLAGS (PROT_READ | PROT_WRITE)                                        
#define M_FLAGS (MAP_PRIVATE | MAP_ANON)

#define HTABLE_BITS 9

DEFINE_HASHTABLE(htable_sid, 9);
DEFINE_HASHTABLE(htable_bid, 9);
DEFINE_HASHTABLE(htable_uid, 9);

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

static struct pages pagemap;

u32 shift = 12, pages = 100000;

int
acct_init(void)
{
	if (pages_alloc(&pagemap, P_FLAGS, M_FLAGS, 12, shift, pages))
		die("pages_alloc() failed reason=%s", strerror(errno));

	return 0;
}

int
acct_fini(void)
{
	pages_free(&pagemap);
	return 0;
}

int
page_copy(struct page *page, struct page *from)
{
	memcpy(page, from, 1 << shift);
	return 0;
}

static void
audit_authentication(struct aaa *aaa, const char *uid)
{
	const char *user  = aaa_attr_get(aaa, "user.name");
	const char *type  = aaa_attr_get(aaa, "auth.type");
	const char *trust = aaa_attr_get(aaa, "auth.trust");
	const char *proto = type ? printfa(", type: %s", type):"";
	const char *authx = trust ? printfa(", trust: %s", trust):"";

	info("The user %s has been authenticated. (uid: %s, protocol: tls%s%s)",
	     user ? user: uid, uid, proto, authx);

}

static int 
session_parse(struct aaa *aaa, byte *buf, unsigned int len)
{
	const char *uid1 = aaa_attr_get(aaa, "user.id");
	const char *uid2 = NULL;
	len--; 
	byte *end = buf + len, *a, *b;
	while (buf < end) {
		byte *key = buf;
		while (buf < end && *buf != ':' && *buf != '\n')
			buf++;
		if (buf >= end)
			goto finish;
		if (*buf != ':')
			goto finish;
		a = buf;
		*buf++ = 0;
		byte *value = buf;
		while (buf < end && *buf != '\n')
			buf++;
		if (buf >= end)
			goto finish;
		b = buf;
		*buf++ = 0;

		struct attr *attr = dict_lookup(&aaa->attrs, key, 0);
		if (!strcmp(key, "user.id"))
			uid2 = value;

		if (attr && (attr->flags & ATTR_CHANGED)) {
			debug3("parse %s:<%s> changed", attr->key, attr->val);
		} else {
			debug3("parse %s:<%s>", key, value);
			dict_set_nf(&aaa->attrs, key, value);
		}
		*a = ':';
		*b = '\n';

	}
	*buf++ = 0;
finish:
	if (!uid2 && uid1)
		audit_authentication(aaa, uid1);
	
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
		debug2("build %s:%s", a->key, a->val);
		if (len > size)
			return -EINVAL;
	}

	debug2("build session size: %d", len);

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
	debug3("session id=%s expired.", session->attrs.sid);
	hash_del(&session->sid);
	memset(((u8*)session) + sizeof(*session), 0, (1 << shift) - sizeof(*session));
	page_free(&pagemap, (struct page *)session);
}

static int
lookup(struct aaa *aaa, struct cursor *sid)
{
	struct session *session = NULL;
	int rv = -1;
	hash_walk_delsafe(htable_sid, sid->slot, session, sid) {
		int exp = session->expires - sid->now;
		if (exp < 1) {
			expired(session);
			continue;
		}

		if (rv == 0)
			continue;

		if (strcmp(sid->id.addr, session->attrs.sid))
			continue;

		debug3("session id=%s attached.", session->attrs.sid);
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
	if (!(page = page_alloc(&pagemap)))
		goto cleanup;

	struct session *session = (struct session *)page;
	memset(((u8*)session) + sizeof(*session), 0, (1 << shift) - sizeof(*session)); 
	session->created = session->modified = sid->now;
	session->expires = session->created + sid->expires;

	set_id(session, sid);
	aaa_attr_set(aaa, "sess.id", (char *)sid->id.addr);
	aaa_attr_set(aaa, "sess.created",  printfa("%lld", (long long int)session->created));
	aaa_attr_set(aaa, "sess.modified", printfa("%lld", (long long int)session->modified));
	aaa_attr_set(aaa, "sess.expires",  printfa("%lld", (long long int)session->expires));

	if (session_write(aaa, session) < 0)
		goto cleanup;
	hash_add(htable_sid, &session->sid, sid->slot);

	debug3("session id=%s created.", session->attrs.sid);
	return 0;
cleanup:
	if (page)
		page_free(&pagemap, page);
	return -EINVAL;
}

int
session_bind(struct aaa *aaa, const char *id)
{
	struct cursor csid;
	struct bb sid = { .addr = (void *)id, .len = strlen(id) };
	acct_cursor(&csid, &sid, aaa->timeout);

        debug3("bind() id=%s slot=%d", sid.addr, (int)csid.slot);
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
	int rv = -1;
	hash_walk_delsafe(htable_sid, sid->slot, session, sid) {
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
	acct_cursor(&csid, &sid, aaa->timeout);

	debug3("commit() id=%s slot=%u processing", sid.addr, (unsigned int)csid.slot);

	if (lookup(aaa, &csid))
		goto failed;

	return commit(aaa, &csid);
failed:
	debug3("commit() id=%s slot=%u failed", sid.addr, (unsigned int)csid.slot);
	return -EINVAL;	
}

int
session_touch(struct aaa *aaa, const char *id)
{
	struct cursor csid;
	struct bb sid = { .addr = (void *)id, .len = strlen(id) };
	acct_cursor(&csid, &sid, aaa->timeout);

	debug3("touch id=%s hash=%d slot=%d", sid.addr, csid.hash, csid.slot);
	if (lookup(aaa, &csid))
		return -EINVAL;

	return commit(aaa, &csid);
}
