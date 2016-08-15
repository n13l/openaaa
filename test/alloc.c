#include <sys/compiler.h>
#include <sys/log.h>
#include <mem/alloc.h>
#include <mem/stack.h>
#include <mem/pool.h>

#define m_va_n_args(...) m_va_n_args_impl(##__VA_ARGS__, 5,4,3,2,1)
#define m_va_n_args_impl(_1, _2, _3, _4, _5, N,...) N

#define m_dispatcher(func, ...) \
	m_dispatcher_(func, m_va_n_args(__VA_ARGS__))
#define m_dispatcher_(func, nargs) \
	m_dispatcher__(func, nargs)
#define m_dispatcher__(func, nargs) \
	func ## nargs

#define xmax1(a) a
#define xmax2(a,b) ((a)>(b)?(a):(b))
#define xmax3(a,b,c) max2(max2(a,b),c)


#define xmax(...) m_dispatcher(vmax, ##__VA_ARGS__)(##__VA_ARGS__)

#define macro_nth_args_(_1, _2, _3, _4, _5, N, ...) N
 
// Count how many args are in a variadic macro. We now use GCC/Clang's extension to
// // handle the case where ... expands to nothing. We must add a placeholder arg before
// // ##__VA_ARGS__ (its value is totally irrelevant, but it's necessary to preserve
// // the shifting offset we want). In addition, we must add 0 as a valid value to be in
// // the N position.
/* Helper macro for macro_args_count */
#define macro_nth_args_(_1, _2, _3, _4, _5, N, ...) N
/* Count how many args are in variadic macro. */
#define macro_args_count(...) macro_nth_args_("",##__VA_ARGS__, 4, 3, 2, 1, 0)

int 
main(int argc, char *argv[]) 
{
	_unused struct mm_pool *mp = mm_pool_create(NULL, CPU_PAGE_SIZE, 0);

	/* explicit stack allocation */
	_unused void *addr1 = mm_alloc(mp, 1024);
	/* implicit stack allocation */
	//_unused void *addr2 = mm_alloc(1024);

	//debug("stack alloc addr1=%p", addr1);
	//debug("stack alloc addr2=%p", addr2);
	//
	debug("zero args: %d", macro_args_count(2));
	debug("three args: %d", macro_args_count(1, 2, 3, 4));
/*
	int a = xmax(1);
	int b = xmax(1,2);
	int c = xmax(1,2,3);

	debug("%d %d %d", a, b, c);
*/
	//mm_destroy(mp);
	//
	return 0;
}
