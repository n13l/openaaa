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

#define OPENSSL_ABI(rv, fn, args...) \
	rv ((*openssl_##fn)(args)); \

#define DECLARE_ABI(fn) \
	abi##_##fn

#define OPENSSL_CALL(fn) \
	openssl##_##fn

#define OPENSSL_LINK(fn) \
	plthook_replace(plt, stringify(fn), abi_##fn, (void**)&openssl_##fn)

typedef void *SSL_METHOD;
typedef void *SSL;
typedef void *SSL_CTX;

void (*info_cb)(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg);

OPENSSL_ABI(int,       SSL_library_init, void);
OPENSSL_ABI(long,      SSLeay, void);
OPENSSL_ABI(SSL_CTX *, SSL_CTX_new, const SSL_METHOD *);
OPENSSL_ABI(void,      SSL_CTX_free, SSL_CTX *);
OPENSSL_ABI(SSL *,     SSL_new, SSL_CTX *);
OPENSSL_ABI(void,      SSL_free, SSL *);
OPENSSL_ABI(int,       SSL_session_reused, SSL *);
OPENSSL_ABI(int,       SSL_set_ex_data, SSL *, int, void *);
OPENSSL_ABI(void *,    SSL_get_ex_data, const SSL *, int);
//OPENSSL_ABI(void,      SSL_CTX_set_msg_callback, SSL_CTX *, void (*callback)());    
//OPENSSL_ABI(void,      SSL_CTX_set_info_callback, SSL_CTX *, void (*callback)());

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

int
DECLARE_ABI(SSL_library_init)(void)
{
	debug("init");
	return OPENSSL_CALL(SSL_library_init)();
}

long
DECLARE_ABI(SSLeay)(void)
{
	return OPENSSL_CALL(SSLeay)();
}

/*
void
DECLARE_ABI(SSL_CTX_set_msg_callback)(SSL_CTX *ctx, void (*callback)())
{
	debug("ctx=%p", ctx);
	OPENSSL_CALL(SSL_CTX_set_msg_callback)(ctx, callback);
}

void
DECLARE_ABI(SSL_CTX_set_info_callback,)(SSL_CTX *ctx, void (*callback)())
{
	debug("ctx=%p", ctx);
	OPENSSL_CALL(SSL_CTX_set_msg_callback)(ctx, callback);
}
*/
int
DECLARE_ABI(SSL_set_ex_data)(SSL *ssl, int index, void *data)
{
	debug("ssl=%p index=%d data=%p", ssl, index, data);
	return OPENSSL_CALL(SSL_set_ex_data)(ssl, index, data);
}

void *
DECLARE_ABI(SSL_get_ex_data)(const SSL *ssl, int index)
{
	void *data = OPENSSL_CALL(SSL_get_ex_data)(ssl, index);
	debug("ssl=%p index=%d data=%p", ssl, index, data);
	return data;
}

SSL_CTX *
DECLARE_ABI(SSL_CTX_new)(const SSL_METHOD *m)
{
	ssl_version();
	return OPENSSL_CALL(SSL_CTX_new)(m);
}

void
DECLARE_ABI(SSL_CTX_free)(SSL_CTX *ctx)
{
	OPENSSL_CALL(SSL_CTX_free)(ctx);
}

SSL *
DECLARE_ABI(SSL_new)(SSL_CTX *ctx)
{
	SSL *ssl = OPENSSL_CALL(SSL_new)(ctx);
	debug("ssl = %p ctx=%p", ssl, ctx);
	return ssl;
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
	if (!plt)
		return;

	OPENSSL_LINK(SSLeay);
	OPENSSL_LINK(SSL_set_ex_data);
	OPENSSL_LINK(SSL_get_ex_data);
	OPENSSL_LINK(SSL_CTX_new);
	OPENSSL_LINK(SSL_CTX_free);
	OPENSSL_LINK(SSL_new);
	OPENSSL_LINK(SSL_free);

	plthook_close(plt);
}
