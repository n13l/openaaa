/*
 * $id: sys/missing.h                                Daniel Kubec <niel@rtfm.cz>
 *
 * This software may be freely distributed and used according to the terms
 * of the GNU Lesser General Public License.
 */

#ifndef __PORTABLE_SYS_MISSING_H__
#define __PORTABLE_SYS_MISSING_H__

#include <sys/compiler.h>
#include <sys/cpu.h>
#include <sys/decls.h>
#include <stdarg.h>

__BEGIN_DECLS

#ifndef O_NOATIME
#define O_NOATIME 0
#endif

#ifndef MAXPATHLEN
#define MAXXPATHLEN 1024
#endif

#ifndef O_NONBLOCK
#define O_NONBLOCK 0x0
#endif

#ifndef assert
#define assert(x)
#endif

void die(const char *str, ...);
void vdie(const char *fmt, va_list args);
void giveup(const char *fmt, ...);

char *
__compat_get_unix_path(char *f);

char *
__compat_get_home_dir(char *str, int size);

__END_DECLS

#endif/*__MEM_MISSING_H__*/
