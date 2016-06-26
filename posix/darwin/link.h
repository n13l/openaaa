#ifndef __POSIX_DARWIN_LINK_H__
#define __POSIX_DARWIN_LINK_H__

struct mach_header;

struct dl_phdr_info {
	void *dlpi_addr;
	const char *dlpi_name;
	const struct mach_header *dlpi_phdr;
	u64 dlpi_phnum;
};

int
dl_iterate_phdr(int (*cb) (struct dl_phdr_info *info, 
                size_t size, void *data), void *data);

#endif
