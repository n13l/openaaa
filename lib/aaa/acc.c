#include <sys/compiler.h>
#include <sys/cpu.h>
#include <mem/page.h>
#include <aaa/lib.h>

/*
define_hashtable(sess_id, 12);
define_hashtable(user_id, 12);

struct session {
	struct page page;
	struct hnode sess_id;
	struct hnode user_id;
	unsigned char obj[];
};
*/
