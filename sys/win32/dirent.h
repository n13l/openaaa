#ifndef __WINDOWS_DIRENT_H__
#define __WINDOWS_DIRENT_H__

#include <stdio.h>
#include <limits.h>

typedef struct DIR DIR;

#define DT_UNKNOWN 0
#define DT_DIR     1
#define DT_REG     2
#define DT_LNK     3

struct dirent {
	long d_ino;
	char d_name[FILENAME_MAX];
	union {
		unsigned short d_reclen;
		unsigned char  d_type;
	};
};

DIR *opendir(const char *dirname);
struct dirent *readdir(DIR *dir);
int closedir(DIR *dir);

#endif/*__WINDOWS_DIRENT_H__*/
