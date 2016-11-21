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

#include <crypto/abi/lib.h>

defn_abi(openssl1, long,         SSLeay, void);
defn_abi(openssl1, const char *, SSLeay_version, int);

struct abi_sym abi_table_openssl1[] = {
	decl_abi_sym(SSLeay,         ABI_CALL_REQUIRE),
	decl_abi_sym(SSLeay_version, ABI_CALL_REQUIRE)
};

decl_abi(openssl1, const char *, SSLeay_version, int v)
{
	return call_abi(openssl1, SSLeay_version, v);
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

int
crypto_openssl(void)
{
	return 0;
}
