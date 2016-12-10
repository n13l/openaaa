#ifndef __WIN32_COMPAT_H__
#define __WIN32_COMPAT_H__

#ifndef ENOENT
# define ENOENT ERROR_PATH_NOT_FOUND
#endif
#ifndef EINVAL
# define EINVAL ERROR_BAD_ARGUMENTS
#endif
#ifndef EAGAIN
# define EAGAIN ERROR_OUTOFMEMORY
#endif
#ifndef EPERM
# define EPERM  ERROR_WRITE_FAULT
#endif
#ifndef EFAULT
# define EFAULT ERROR_INVALID_ADDRESS
#endif
#ifndef ENOMEM
# define ENOMEM ERROR_NOT_ENOUGH_MEMORY
#endif
#ifndef ERANGE
# define ERANGE ERROR_INVALID_DATA
#endif

#endif
