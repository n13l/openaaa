#ifndef __DARWIN_LINK_H__
#define __DARWIN_LINK_H__

struct dl_phdr_info {
	void *dlpi_addr;
	const char *dlpi_name;
};

int
dl_iterate_phdr(int (*cb) (struct dl_phdr_info *info, size_t size, void *data),
                void *data);

#endif
