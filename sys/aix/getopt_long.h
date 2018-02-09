#ifndef _GETOPT_H
#define _GETOPT_H 1

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

#define THIS_IS__STDC__ 1

#if !HAVE_DECL_GETOPT

extern char *optarg;

extern int optind;

extern int opterr;

extern int optopt;

#endif 

#if !HAVE_DECL_GETOPT_LONG

struct option
{
#if defined (THIS_IS__STDC__) && THIS_IS__STDC__
  const char *name;
#else
  char *name;
#endif
  int has_arg;
  int *flag;
  int val;
};

#define	no_argument		0
#define required_argument	1
#define optional_argument	2

#endif 

#if defined (THIS_IS__STDC__) && THIS_IS__STDC__
#if defined (__GNU_LIBRARY__) || (defined (HAVE_DECL_GETOPT) && !HAVE_DECL_GETOPT)
extern int getopt (int argc, char *const *argv, const char *shortopts);
#else 
# if !defined (HAVE_DECL_GETOPT)
extern int getopt ();
# endif
#endif 
#if !HAVE_DECL_GETOPT_LONG
extern int getopt_long (int argc, char *const *argv, const char *shortopts,
		        const struct option *longopts, int *longind);
extern int getopt_long_only (int argc, char *const *argv,
			     const char *shortopts,
		             const struct option *longopts, int *longind);

/* Internal only.  Users should not call this directly.  */
extern int _getopt_internal (int argc, char *const *argv,
			     const char *shortopts,
		             const struct option *longopts, int *longind,
			     int long_only);
#endif 
#else 
#if !HAVE_DECL_GETOPT
extern int getopt ();
#endif 
#if !HAVE_DECL_GETOPT_LONG
extern int getopt_long ();
extern int getopt_long_only ();

extern int _getopt_internal ();
#endif 
#endif


#ifdef	__cplusplus
}
#endif

#endif /* getopt.h */
