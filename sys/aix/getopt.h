#ifndef __OS390_GETOPT_H
#define __OS390_GETOPT_H

#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 
#endif

#include <stdio.h>
int getopt(int argc, char *const argv[], const char *optsting);

extern char *optarg; 
extern int optind, opterr, optopt;

struct option
{
# if defined __STDC__ && __STDC__
  const char *name;
# else
  char *name;
# endif
  /* has_arg can't be an enum because some compilers complain about
     type mismatches in all the code that assumes it is an int.  */
  int has_arg;
  int *flag;
  int val;
};

/* Names for the values of the `has_arg' field of `struct option'.  */

# define no_argument		0
# define required_argument	1
# define optional_argument	2
//#endif	/* need getopt */

#endif
