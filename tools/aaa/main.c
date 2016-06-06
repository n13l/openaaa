/*                                                                              
 * (AAA) Command Line Tool
 *
 * The MIT License (MIT)         Copyright (c) 2015 Daniel Kubec <niel@rtfm.cz> 
 *                                                                              
 * Permission is hereby granted, free of charge, to any person obtaining a copy 
 * of this software and associated documentation files (the "Software"),to deal 
 * in the Software without restriction, including without limitation the rights 
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell    
 * copies of the Software, and to permit persons to whom the Software is        
 * furnished to do so, subject to the following conditions:                     
 *                                                                              
 * The above copyright notice and this permission notice shall be included in   
 * all copies or substantial portions of the Software.                          
 *                                                                              
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR   
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,     
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE  
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER       
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,ARISING FROM, 
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN    
 * THE SOFTWARE.                                                                
 */

#include <sys/compiler.h>
#include <sys/cpu.h>
#include <sys/link.h>
#include <sys/log.h>
#include <asm/cache.h>
#include <asm/instr.h>
#include <mem/list.h>
#include <mem/pool.h>
#include <mem/page.h>
#include <mem/stack.h>

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <libgen.h>
#include <dlfcn.h>

#include <link.h>

#include <sys/abi.h>
#include <aaa/lib.h>

#include <tramp.h>

defn_abi(openssl, long,         SSLeay, void);
defn_abi(openssl, const char *, SSLeay_version, int);

decl_abi(openssl, const char *, SSLeay_version, int v)
{
	return call_abi(openssl, SSLeay_version, v);
}

struct abi_sym abi_table_openssl[] = {
	decl_abi_sym(SSLeay,         ABI_CALL_REQUIRE),
	decl_abi_sym(SSLeay_version, ABI_CALL_REQUIRE)
};

void
ssl_version(void)
{
	long version = call_abi(openssl, SSLeay);

	byte major = version >> 28 & 0xFF;
	byte minor = version >> 20 & 0xFF;
	byte patch = version >> 12 & 0XFF;
	byte dev   = version >> 04 & 0XFF;

	sys_dbg("openssl-%d.%d.%d%c", major, minor, patch, 'a' + dev - 1);
}

void
die(const char *fmt, ...)
{
	exit(1);
}

int
main(int argc, char *argv[])
{
#ifdef CONFIG_DARWIN	
	const char *file = "/opt/local/lib/libssl.dylib";
#endif
#ifdef CONFIG_WIN32
	const char *file = "libssl.dll";
#endif
#ifdef CONFIG_LINUX
	const char *file = "/usr/lib64/libssl.so";
#endif
	sys_dbg("dll file=%s", file);
	void *dll = dlopen(file, RTLD_NOW);

	if (!dll)
		return 0;

	linkmap_init();

	defn_abi_link(dll, SSLeay);
	defn_abi_link(dll, SSLeay_version);

	arch_dbg("symbol: %p", sym_SSLeay_version);

	arch_call_interpose(sym_SSLeay_version, abi_openssl_SSLeay_version);

	ssl_version();

	return 0;
}
