/*
 * The MIT License (MIT)                            OpenSSL Runtime ABI Support
 *                               Copyright (c) 2015 Daniel Kubec <niel@rtfm.cz> 
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
#include <sys/abi.h>
#include <sys/log.h>
#include <stdlib.h>
#include <stdio.h>

#ifndef _GNU_SOURCE
#define _GNU_SOURCE         /* See feature_test_macros(7) */
#endif
#include <link.h>
#include <crypto/abi/lib.h>

#define DEFINE_ABI_call(rv, fn, args...) \
	rv ((*abi_##fn)(args)); \

#define DEFINE_ABI(ns, rv, fn, args...) \
	rv ((* openssl_##fn)(args)); \

#define decl_abi_sym(ns, fn, mode) \
	{ stringify(fn), &ns_##fn, mode } 

#define call_abi(ns, fn, args...) \
	ns_##fn(args)

#define defn_abi_call(rv, fn, args...) \
	rv ((*abi_##fn)(args)); \


typedef void *SSL_METHOD;
typedef void *SSL;
typedef void *SSL_CTX;

DEFINE_ABI(openssl, long,         SSLeay, void);
DEFINE_ABI(openssl, const char *, SSLeay_version, int);
DEFINE_ABI(openssl, SSL_CTX *,    SSL_CTX_new, const SSL_METHOD *);
DEFINE_ABI(openssl, void,         SSL_CTX_free, SSL_CTX *);
DEFINE_ABI(openssl, SSL *,        SSL_new, SSL_CTX *);
DEFINE_ABI(openssl, void,         SSL_free, SSL *);
DEFINE_ABI(openssl, int,          SSL_session_reused, SSL *);

/*
struct abi_sym abi_table_openssl1[] = {
	decl_abi_sym(SSLeay,         ABI_CALL_REQUIRE),
	decl_abi_sym(SSLeay_version, ABI_CALL_REQUIRE)
};
*/

/*
decl_abi(openssl, const char *, SSLeay_version, int v)
{
	return call_abi(openssl, SSLeay_version, v);
}

static _unused void
ssl_version(void)
{
	long version = call_abi(openssl, SSLeay);

	byte major = (version >> 28) & 0xFF;
	byte minor = (version >> 20) & 0xFF;
	byte patch = (version >> 12) & 0XFF;
	byte dev   = (version >>  4) & 0XFF;

	sys_dbg("openssl-%d.%d.%d%c", major, minor, patch, 'a' + dev - 1);
}
*/
void
dump_symbol(void *addr)
{
	Dl_info info;
	dladdr(addr, &info);

	debug("base=%p", info.dli_fbase);
	debug("name=%s module=%s", info.dli_sname, info.dli_fname);
}

int
crypto_module(struct dl_phdr_info *info, size_t size, void *data)
{
	if (!info->dlpi_name || !*info->dlpi_name)
		return 0;
	debug("module name=%s", info->dlpi_name);
	return 0;
}
	
void
crypto_lookup(void)
{
	debug("checking for openssl crypto");

	openssl_SSLeay_version = dlsym(RTLD_DEFAULT,"SSLeay_version");
	if (!openssl_SSLeay_version)
		return;

	openssl_SSLeay = dlsym(RTLD_DEFAULT,"SSL_new");
	if (!openssl_SSLeay)
		return;

	dump_symbol(crypto_lookup);
	dump_symbol(openssl_SSLeay_version);
	dump_symbol(openssl_SSLeay);
}
