#include <sys/compiler.h>
#include <sys/log.h>
#include <sys/types.h>
#include <sys/ldr.h>
#include <stdlib.h>
#include <stdio.h>

/*
 *
 * struct ld_xinfo
 *
 * __ptr64     ldinfo_textorg;          start of loaded program image
 *                                      (includes the XCOFF headers) 
 * uint64_t    ldinfo_textsize;         length of loaded program image 
 * __ptr64     ldinfo_dataorg;          start of data 
 * uint64_t    ldinfo_datasize;         size of data 
 * uint64_t    ldinfo_tdatasize;        size of tdata 
 * uint64_t    ldinfo_tbsssize;         size of tbss 
 * __ptr64     ldinfo_tdataorg;         start of initial tdata 
 * uint64_t    ldinfo_tdataoff;         Offset in TLS region to tdata 
 * uint        ldinfo_tls_rnum;         TLS region number 
*/

int
dl_iterate_phdr(int (*cb)(struct dl_phdr_info *dpi, size_t size, void *ptr), 
		void *ctx)
{
	struct dl_phdr_info dpi;
	char *p = alloca(64000);
	int rv;

	if ((rv = loadquery((int)L_GETXINFO, p, 64000)) == -1) {
		error("err: %s", strerror(errno));
		return rv;
	}

	for (struct ld_xinfo *x = p; x->ldinfo_next; p += x->ldinfo_next) {
		x = (struct ld_xinfo*)p;
		dpi.dlpi_name = ((u8*)x) + x->ldinfo_filename;
		dpi.dlpi_addr = x->ldinfo_textorg;
		cb(&dpi, sizeof(dpi), ctx);
	}
 
	return 0;
}

