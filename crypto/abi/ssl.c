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
#include <sys/plt/plthook.h>
#include <net/tls/ext.h>
#include <crypto/abi/lib.h>
#include <unix/list.h>

/* We dont't link agaist openssl but using important signatures */
#include <crypto/abi/openssl/ssl.h>
#include <crypto/abi/openssl/bio.h>

#define DEFINE_ABI(fn) \
	struct plt_##fn { \
		const char *name; struct node node; \
		typeof(fn) *abi_##fn; typeof(fn) *plt_##fn; \
	} plt_##fn = { \
		.name     = stringify(fn), .node = DECLARE_INIT_NODE, \
		.abi_##fn = NULL, .plt_##fn = NULL \
	}

#define DEFINE_ABI_CALL(fn) abi_##fn
#define CALL_ABI(fn) plt_##fn.plt_##fn

#define IMPORT_ABI(fn) \
	plt_##fn.abi_##fn = (typeof(plt_##fn.abi_##fn))abi_##fn; \
	plthook_replace(plt, stringify(fn), abi_##fn, (void**)&plt_##fn.plt_##fn)

DECLARE_LIST(openssl_abi);

DEFINE_ABI(SSLeay);
DEFINE_ABI(SSL_CTX_new);
DEFINE_ABI(SSL_CTX_free);
DEFINE_ABI(SSL_new);
DEFINE_ABI(SSL_free);
DEFINE_ABI(SSL_set_ex_data);
DEFINE_ABI(SSL_get_ex_data);
DEFINE_ABI(SSL_CTX_set_msg_callback);
DEFINE_ABI(SSL_CTX_set_info_callback);
DEFINE_ABI(SSL_set_msg_callback);
DEFINE_ABI(SSL_set_info_callback);
DEFINE_ABI(SSL_export_keying_material);
DEFINE_ABI(SSL_state_string);
DEFINE_ABI(SSL_state_string_long);
DEFINE_ABI(SSL_alert_type_string);
DEFINE_ABI(SSL_alert_type_string_long);
DEFINE_ABI(SSL_alert_desc_string);
DEFINE_ABI(SSL_alert_desc_string_long);
DEFINE_ABI(SSL_get_error);
DEFINE_ABI(SSL_get_session);
DEFINE_ABI(SSL_SESSION_free);
DEFINE_ABI(SSL_SESSION_get_id);
DEFINE_ABI(SSL_SESSION_print);
DEFINE_ABI(BIO_new);
DEFINE_ABI(BIO_free);
DEFINE_ABI(BIO_s_mem);
DEFINE_ABI(BIO_ctrl);
DEFINE_ABI(BIO_read);
DEFINE_ABI(X509_NAME_oneline);
DEFINE_ABI(SSL_get_ex_data_X509_STORE_CTX_idx);
DEFINE_ABI(X509_STORE_CTX_get_ex_data);
DEFINE_ABI(SSL_callback_ctrl);
DEFINE_ABI(SSL_get_peer_certificate);
DEFINE_ABI(SSL_get_certificate);
DEFINE_ABI(SSL_get_SSL_CTX);
DEFINE_ABI(SSL_CTX_get_cert_store);
DEFINE_ABI(SSL_extension_supported);


void (*ssl_info_callback)  (SSL *s, int, int) = NULL;
void (*ssl_tlsext_callback)(SSL *s, int client_server, 
                                int type, unsigned char *data, 
                                int len, void *arg) = NULL;

typedef void (*openssl_msg_cb)
(int wp, int ver, int type, const void *buf, size_t len, SSL *ssl, void *arg);
typedef void (*openssl_info_cb)
(const SSL *s, int where, int ret);

static void
ssl_version(void)
{
	long version = CALL_ABI(SSLeay)();

	byte major = (version >> 28) & 0xFF;
	byte minor = (version >> 20) & 0xFF;
	byte patch = (version >> 12) & 0XFF;
	byte dev   = (version >>  4) & 0XFF;

	debug("openssl-%d.%d.%d%c", major, minor, patch, 'a' + dev - 1);
}

long
DEFINE_ABI_CALL(SSLeay)(void)
{
	return CALL_ABI(SSLeay)();
}

void
DEFINE_ABI_CALL(SSL_CTX_set_msg_callback)(SSL_CTX *ctx, openssl_msg_cb msg)
{
	debug("ctx=%p", ctx);
	CALL_ABI(SSL_CTX_set_msg_callback)(ctx, msg);
}

void
DEFINE_ABI_CALL(SSL_CTX_set_info_callback)(SSL_CTX *ctx, openssl_info_cb cb)
{
	debug("ctx=%p", ctx);
	CALL_ABI(SSL_CTX_set_info_callback)(ctx, cb);
}

void
DEFINE_ABI_CALL(SSL_set_msg_callback)(SSL *ssl, openssl_msg_cb msg)
{
	debug("ssl=%p", ssl);
	CALL_ABI(SSL_set_msg_callback)(ssl, msg);
}

void
DEFINE_ABI_CALL(SSL_set_info_callback)(SSL *ssl, openssl_info_cb cb)
{
	debug("ssl=%p", ssl);
	CALL_ABI(SSL_set_info_callback)(ssl, cb);
}

int
DEFINE_ABI_CALL(SSL_set_ex_data)(SSL *ssl, int index, void *data)
{
	debug("ssl=%p index=%d data=%p", ssl, index, data);
	return CALL_ABI(SSL_set_ex_data)(ssl, index, data);
}

void *
DEFINE_ABI_CALL(SSL_get_ex_data)(const SSL *ssl, int index)
{
	void *data = CALL_ABI(SSL_get_ex_data)(ssl, index);
	debug("ssl=%p index=%d data=%p", ssl, index, data);
	return data;
}

SSL_CTX *
DEFINE_ABI_CALL(SSL_CTX_new)(const SSL_METHOD *m)
{
	debug("method=%p", m);
	ssl_version();
	return CALL_ABI(SSL_CTX_new)(m);
}

void
DEFINE_ABI_CALL(SSL_CTX_free)(SSL_CTX *ctx)
{
	debug("ctx=%p", ctx);
	CALL_ABI(SSL_CTX_free)(ctx);
}

SSL *
DEFINE_ABI_CALL(SSL_new)(SSL_CTX *ctx)
{
	SSL *ssl = CALL_ABI(SSL_new)(ctx);
	debug("ssl = %p ctx=%p", ssl, ctx);
	return ssl;
}

void
DEFINE_ABI_CALL(SSL_free)(SSL *ssl)
{
	debug("ssl = %p", ssl);
	return CALL_ABI(SSL_free)(ssl);
}

void
crypto_lookup(void)
{
	plthook_t *plt;
	plthook_open(&plt, NULL);
	if (!plt)
		return;

	IMPORT_ABI(SSLeay);
	IMPORT_ABI(SSL_set_ex_data);
	IMPORT_ABI(SSL_get_ex_data);
	IMPORT_ABI(SSL_CTX_new);
	IMPORT_ABI(SSL_CTX_free);
	IMPORT_ABI(SSL_new);
	IMPORT_ABI(SSL_free);
	IMPORT_ABI(SSL_CTX_set_msg_callback);
	IMPORT_ABI(SSL_CTX_set_info_callback);
	IMPORT_ABI(SSL_set_msg_callback);
	IMPORT_ABI(SSL_set_info_callback);

	plthook_close(plt);
}
