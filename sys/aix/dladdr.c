#include <sys/compiler.h>
#include <sys/log.h>
#include <sys/types.h>
#include <sys/ldr.h>
#include <stdlib.h>
#include <stdio.h>

int
dladdr(void* s, Dl_info* i) 
{
	size_t bufSize = 40960;
	struct ld_info* ldi;
	void *buf;
	int r;

	debug4("sym at %lu", (ulong)s);
	buf = (void *)malloc(bufSize);
	if (!buf) {
		i->dli_fname = 0;
		return 0;
	}

	r = loadquery((int)L_GETINFO,  buf,  (int)bufSize);
	if (r == -1) {
		i->dli_fname = 0;
		return 0;
	}

	do {
		ldi = (struct ld_info*)buf;
		debug4("checking %s, text %lu - %lu\n", ldi->ldinfo_filename, 
		      (ulong)ldi->ldinfo_textorg, 
		      (ulong)(ldi->ldinfo_textorg + ldi->ldinfo_textsize));

		if ((ldi->ldinfo_textorg <= s) && 
		   (s < (ldi->ldinfo_textorg + ldi->ldinfo_textsize))) {
			i->dli_fname = ldi->ldinfo_filename;
			return 1;
		}
		buf += ldi->ldinfo_next;
	} while (ldi->ldinfo_next);
	i->dli_fname = 0;
	return 0;
}
