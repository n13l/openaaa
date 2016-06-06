#ifndef __COMPAT_SYS_CDECL_H__
#define __COMPAT_SYS_CDECL_H__

#if defined(__cplusplus)
# ifdef __DECLS_NAMESPACE
#  define __BEGIN_DECLS namespace __DECLS_NAMESPACE { extern "C" {
#  define __END_DECLS }}
# else
#  define __BEGIN_DECLS extern "C" {
#  define __END_DECLS   }
# endif
#else
# define __BEGIN_DECLS
# define __END_DECLS
#endif

#ifndef __BEGIN_DECLS
#define __BEGIN_DECLS
#endif

#ifndef __END_DECLS
#define __END_DECLS
#endif

#endif/*__COMPAT_SYS_CDECL_H__*/
