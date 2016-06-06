#ifndef __WINDOWS_DLFCN_H__
#define __WINDOWS_DLFCN_H__

#define RTLD_LAZY       0
#define RTLD_NOW        0
#define RTLD_GLOBAL     (1 << 1)
#define RTLD_LOCAL      (1 << 2)
#define RTLD_DEFAULT    0
#define RTLD_NEXT       0

/* _GNU_SOURCE extensions */
typedef struct {
	const char *dli_fname;
	void *dli_fbase;      
	const char *dli_sname;
	void *dli_saddr;      
} Dl_info;

struct dl_phdr_info {
	void *dlpi_addr;  
	const char *dlpi_name;
};

void *
dlopen(const char *file, int mode);

int
dlclose(void *handle);

void *
dlsym(void *handle, const char *name);

char *
dlerror(void);

int
dladdr(void *addr, Dl_info *info);

int
dl_iterate_phdr(int (*cb)(struct dl_phdr_info *, size_t , void *), void *);

#endif/*__WINDOWS_DLFCN_H__ */
