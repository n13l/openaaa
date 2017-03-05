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
#include <sys/plt/plthook.h>

#define DEFINE_ABI(ns, rv, fn, args...) \
	rv ((*ns##_##fn)(args)); \

#define DECLARE_ABI(fn) \
	abi##_##fn

#define OPENSSL_CALL(fn) \
	openssl##_##fn

#define OPENSSL_LINK(fn) \
	plthook_replace(plt, stringify(fn), abi_##fn, (void**)&openssl_##fn)

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

static void
ssl_version(void)
{
	long version = OPENSSL_CALL(SSLeay)();

	byte major = (version >> 28) & 0xFF;
	byte minor = (version >> 20) & 0xFF;
	byte patch = (version >> 12) & 0XFF;
	byte dev   = (version >>  4) & 0XFF;

	debug("openssl-%d.%d.%d%c", major, minor, patch, 'a' + dev - 1);
}

long
DECLARE_ABI(SSLeay)(void)
{
	return OPENSSL_CALL(SSLeay)();
}

SSL *
DECLARE_ABI(SSL_new)(SSL_CTX *ctx)
{
	debug("ctx = %p", ctx);
	ssl_version();
	return OPENSSL_CALL(SSL_new)(ctx);
}

void
DECLARE_ABI(SSL_free)(SSL *ssl)
{
	debug("ssl = %p", ssl);
	return OPENSSL_CALL(SSL_free)(ssl);
}

void
crypto_lookup(void)
{
	plthook_t *plt;
	plthook_open(&plt, NULL);

	OPENSSL_LINK(SSLeay);
	OPENSSL_LINK(SSL_new);
	OPENSSL_LINK(SSL_free);

	plthook_close(plt);
}
