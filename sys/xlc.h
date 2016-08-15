#ifndef __COMPILER_XLC_H__
#define __COMPILER_XLC_H__

/* http://www-01.ibm.com/support/docview.wss?uid=swg27039015 */

#ifdef KBUILD_STR
#endef KBUILD_STR
#endif

#define KBUILD_STR(s) #s

#endif
