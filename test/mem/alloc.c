#include <sys/compiler.h>
#include <sys/log.h>
#include <mem/alloc.h>
#include <mem/stack.h>
#include <mem/pool.h>

#define m_va_n_args(...) m_va_n_args_impl(__VA_ARGS__, 5,4,3,2,1)
#define m_va_n_args_impl(_1, _2, _3, _4, _5, N,...) N

#define m_dispatcher(func, ...) \
	m_dispatcher_(func, m_va_n_args(__VA_ARGS__))
#define m_dispatcher_(func, nargs) \
	m_dispatcher__(func, nargs)
#define m_dispatcher__(func, nargs) \
	func ## nargs

/* Helper macro for macro_args_count based on GCC/Clang's extension */
#define macro_nth_args_(_1, _2, _3, _4, _5, N, ...) N
/* Count how many args are in variadic macro. */
#define macro_args_count(...) macro_nth_args_("", ## __VA_ARGS__, 4, 3, 2, 1, 0)

int 
main(int argc, char *argv[]) 
{
	_unused struct mm_pool *mp = mm_pool_create(CPU_PAGE_SIZE, 0);

	/* explicit stack allocation */
	_unused void *addr1 = mm_pool_alloc(mp, 1024);
	/* implicit stack allocation */
	// _unused void *addr2 = mm_alloc(1024);
/*
	_unused void *addr3 = mm_zalloc(1024);
	_unused void *addr4 = mm_zalloc(mp, 1024);

	char *s = mm_strdup(mp, "hi");

	debug("zero args: %d", macro_args_count());
	debug("three args: %d", macro_args_count(1, 2, 3, 4));
	*/
	//mm_destroy(mp);
	return 0;
}
