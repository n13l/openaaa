#ifndef _LIBGEN_H_
#define _LIBGEN_H_

#include <stdlib.h>
#include <stdio.h>

#undef basename
#define basename __xpg_basename
char *basename(char *file);
char *dirname(char *file);

#endif /* _LIBGEN_H_ */

