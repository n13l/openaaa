#ifndef __MM_POOL_H__
#define __MM_POOL_H__

#include <sys/compiler.h>

struct std_mem_pool; /* memory generic pool                       */
struct map_mem_pool; /* memory mapped pool                        */
struct cpu_mem_pool; /* memory pool supported by cpu instructions */
struct mem_pool;     /* generic memory pool structure             */

#define __mp_alloc(X) _generic((X), struct mmpool: __mm_mp_alloc, \
                                    default: sayother)(X)

#endif
