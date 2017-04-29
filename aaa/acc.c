#include <sys/compiler.h>
#include <sys/cpu.h>
#include <mem/alloc.h>
#include <mem/page.h>
#include <mem/map.h>

#include <aaa/lib.h>
#include <aaa/prv.h>

#include <buffer.h>
#include <list.h>
#include <hash.h>

DEFINE_HASHTABLE(htable_sid, 9);
DEFINE_HASHTABLE(htable_bid, 9);
DEFINE_HASHTABLE(htable_uid, 9);

struct attrs {
	struct bb sid;
	struct bb uid;
};

struct session {
	struct page page;
	struct hnode sid;
	struct hnode uid;
	struct hnode bid;
        timestamp_t created;
        timestamp_t modified;
        timestamp_t access;
        timestamp_t expires;
	char s_sid[64];
	char s_uid[64];
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

struct pagemap *pagemap = NULL;

timestamp_t
get_time(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv.tv_sec;
}

int
session_init(void)
{
	u32 shift = 12, pages = 32768;
	pagemap = mmap_open(NULL, MAP_SHARED | MAP_ANON, shift, pages);
	if (!pagemap)
		die("mm_open() failed reason=%s", strerror(errno));

	debug3("mm area=%p shift=%d pagesize=%d pages=%d size=%lu MB(s)", 
		pagemap, shift, (1 << shift), pages, pages2mb(shift, pages));

	return 0;
}

int
session_fini(void)
{
	if (pagemap)
		mmap_close(pagemap);
	return 0;
}

static inline void
session_time_init(struct session *session, int expires)
{
	session->created = session->modified = session->access = get_time();
	session->expires = session->access + expires;
}

static struct session *
session_lookup(const char *id, int expires)
{
	struct session *session = NULL, *item = NULL;
	u32 h = hash_string(id);

	struct hnode *it = NULL;
	hash_for_each_item_safe(htable_sid, item, it , sid, h) {
		struct bb *sid = &session->attrs.sid;
		if (strncmp(id, sid->addr, sid->len))
			continue;
		session = item;
	}

	return session;
}

static struct session *
session_create(const char *id, int expires)
{
	struct page *page = page_alloc_safe(pagemap);
	if (!page)
		return NULL;

	struct session *session = (struct session *)page;
	strncpy(session->s_sid, id, sizeof(session->s_sid));

	session->attrs.sid.addr = session->s_sid;
	session->attrs.sid.len  = strlen(session->s_sid);
	session_time_init(session, expires);

	debug3("sess.id=%s", session->attrs.sid.addr);
	debug3("sess.created=%jd", (intmax_t)session->created);
	debug3("sess.modified=%jd", (intmax_t)session->modified);
	debug3("sess.access=%jd", (intmax_t)session->access);
	debug3("sess.expires=%jd", (intmax_t)session->expires);

	debug3("expires in %jd sec(s)", session->expires - session->access);

	strncpy(session->s_sid, id, sizeof(session->s_sid));
	return NULL;
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
page_copy(struct page *page, struct page *to)
{
	page_lock(page);

	page_unlock(page);
	return 0;
}

int
session_read(struct aaa *aaa, struct session *session)
{
	return 0;
}

int
session_write(struct aaa *aaa, struct session *session)
{
	return 0;
}

int
session_bind(struct aaa *aaa, const char *id, int type)
{
	u32 expires = 60;
	u32 hash = hash_string(id);
	u32 slot = hash_data(htable_sid, hash);

	debug3("hash=%d slot=%d", hash, slot);

        struct session *session;
        do {
		if (((session = session_lookup(id, expires))))
			break;
		if (!(session = session_create(id, expires)))
			break;
	} while(0);

	return 0;
}

int
session_touch(struct msg *msg)
{
	return 0;
}
