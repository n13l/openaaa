#ifndef __SYS_PLATFORM_H__
#define __SYS_PLATFORM_H__

#define SHLIB_EX           "dylib"

#define HAVE_STRING_H

int
mremap(void *addr, int size , int , int);

#endif
