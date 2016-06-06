/*
 * $lib.h                                      Daniel Kubec <niel@rtfm.cz> 
 *
 * This software may be freely distributed and used according to the terms
 * of the GNU Lesser General Public License.
 */

#ifndef __AAA_OPENVPN_LIB_H__
#define __AAA_OPENVPN_LIB_H__

#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/decls.h>

__BEGIN_DECLS

/* API version, they compare as integers */
#define API_VERSION PACKAGE_VERSION

/* a private structures containing the context */
struct openvpn;

void
openvpn_init(void);

void
openvpn_fini(void);

__END_DECLS

#endif/*__AAA_OPENVPN_LIB_H__*/
