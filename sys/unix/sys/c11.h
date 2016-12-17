#ifndef __COMPILER_C11_H__
#define __COMPILER_C11_H__

/* Get the name of a type */
#define typename(x) _Generic((x),                                             \
                                                                              \
        _Bool:"_Bool",                 unsigned char:"unsigned char",         \
         char:"char",                    signed char:"signed char",           \
    short int:"short int",        unsigned short int:"unsigned short int",    \
          int:"int",                    unsigned int:"unsigned int",          \
     long int:"long int",          unsigned long int:"unsigned long int",     \
long long int:"long long int",unsigned long long int:"unsigned long long int",\
        float:"float",                        double:"double",                \
  long double:"long double",                  char *:"pointer to char",       \
       void *:"pointer to void",               int *:"pointer to int",        \
      default:"other")

#define typecomp(x, T) _Generic((x), T:1, default: 0)

#endif
