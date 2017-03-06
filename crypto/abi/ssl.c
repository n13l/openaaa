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

#include <mem/stack.h>

#include <dlfcn.h>
#include <sys/plt/plthook.h>
#include <net/tls/ext.h>
#include <crypto/abi/lib.h>
#include <unix/list.h>

/* We dont't link agaist openssl but using important signatures */
#include <crypto/abi/openssl/ssl.h>
#include <crypto/abi/openssl/bio.h>
#include <crypto/abi/openssl/tls1.h>

#define SSL_CTXT_GET(ctx) \
	(struct ssl_ctxt *)CALL_ABI(SSL_CTX_get_ex_data)(ctx, 0)

#define SSL_SESS_GET(ssl) \
	(struct ssl_sess *)CALL_ABI(SSL_get_ex_data)(ssl, 0)

DECLARE_LIST(ssl_syms);

DEFINE_ABI(SSLeay);
DEFINE_ABI(SSL_CTX_new);
DEFINE_ABI(SSL_CTX_free);
DEFINE_ABI(SSL_CTX_callback_ctrl);
DEFINE_ABI(SSL_CTX_set_ex_data);
DEFINE_ABI(SSL_CTX_get_ex_data);
DEFINE_ABI(SSL_CTX_add_client_custom_ext);
DEFINE_ABI(SSL_CTX_add_server_custom_ext);
DEFINE_ABI(SSL_new);
DEFINE_ABI(SSL_free);
DEFINE_ABI(SSL_callback_ctrl);
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
DEFINE_ABI(SSL_get_peer_certificate);
DEFINE_ABI(SSL_get_certificate);
DEFINE_ABI(SSL_get_SSL_CTX);
DEFINE_ABI(SSL_CTX_get_cert_store);
DEFINE_ABI(SSL_extension_supported);

typedef void
(*ssl_cb_ext)(const SSL *ssl, int client, int type, byte *data, int len, void *arg);

typedef void (*ssl_cb_msg)
(int wp, int ver, int type, const void *buf, size_t len, SSL *ssl, void *arg);
typedef void (*ssl_cb_info)(const SSL *s, int where, int ret);


enum ssl_endpoint_type {
	TLS_EP_PEER   = 0,
	TLS_EP_CLIENT = 1,
	TLS_EP_SERVER = 2	
};

struct ssl_cb {
	ssl_cb_msg cb_msg;
	ssl_cb_info cb_info;
	ssl_cb_ext cb_ext;
};

struct ssl_aaa {
	char *authority;
};

struct ssl_ctxt {
	SSL_CTX *ctx;
	struct ssl_aaa aaa;
	struct ssl_cb cb;
};

struct ssl_sess {
	SSL_CTX *ctx;
	SSL *ssl;
	struct ssl_ctxt *ssl_ctxt;
	struct ssl_aaa aaa;
	struct ssl_cb cb;
	enum ssl_endpoint_type endpoint;
};

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

void
ssl_extension(const SSL *ssl, int client, int type, 
              unsigned char *data, int len, void *arg)
{ 
	struct ssl_sess *ssl_sess = SSL_SESS_GET(ssl);
	ssl_sess->endpoint = client ? TLS_EP_CLIENT : TLS_EP_SERVER;

	debug("extension name=%s type=%d, len=%d endpoint=%d", 
	       tls_strext(type), type, len, client);
}


int
ssl_ext_srv_add(SSL *ssl, unsigned int type,
                const unsigned char **out, size_t *outlen, int *al, void *arg)
{
	struct ssl_sess *ssl_sess = SSL_SESS_GET(ssl);
	const char *authority = ssl_sess->ssl_ctxt->aaa.authority;
	if (!authority)
		return 0;

	debug("extension name=%s type=%d send [%s]",
	        tls_strext(type), type, authority);	

	*out = authority;
	*outlen = authority ? strlen(authority) : 0;
	return 1;
}

int
ssl_ext_srv_parse(SSL *s, unsigned int type,
                  const unsigned char *in, size_t inlen, int *al, void *arg)
{
	const char *v = sp_strndup(in, inlen);
	debug("extension name=%s type=%d recv [%s]",tls_strext(type), type, v);
	return 1;
}


int
ssl_ext_cli_add(SSL *s, unsigned int type,
                const unsigned char **out, size_t *outlen, int *al, void *arg)
{
	const char *v = "protocol=aaa";
	debug("extension name=%s type=%d send [%s]",tls_strext(type), type, v);

	*out = v;
	*outlen = strlen(v);
	return 1;
}

int
ssl_ext_cli_parse(SSL *ssl, unsigned int type,
                  const unsigned char *in, size_t inlen, int *al, void *arg)
{
	struct ssl_sess *ssl_sess = SSL_SESS_GET(ssl);

	const char *v = sp_strndup(in, inlen);
	debug("extension name=%s type=%d recv [%s]", tls_strext(type), type, v);

	switch (type) {
	case TLS_EXT_SUPPLEMENTAL_DATA:
		if (ssl_sess->aaa.authority)
			free(ssl_sess->aaa.authority);
		ssl_sess->aaa.authority = strdup(v);
		break;
	}

	return 1;
}


const char *
ssl_get_value_desc(const SSL *s, int code)
{
	return NULL;
}

static void
ssl_info_state(const SSL *s, const char *str)
{
	char *d = sp_printf("%s:%s", str, CALL_ABI(SSL_state_string_long)(s));
	debug("msg:%s", d);
}

static void
ssl_info_alert(int where, int rv)
{
	char *desc = sp_printf("alert %s:%s:%s", (where & SSL_CB_READ) ?
	                        "read" : "write",
	                        CALL_ABI(SSL_alert_type_string_long)(rv),
	                        CALL_ABI(SSL_alert_desc_string_long)(rv));

	debug("msg:%s", desc);		
}

static void
ssl_info_failed(const SSL *s, const char *str, int rv)
{
	char *err = sp_printf("%s:failed in %s", str,
	                       CALL_ABI(SSL_state_string_long)(s));

	const char *desc = ssl_get_value_desc(s, rv);
	debug("msg:%s %s", err, desc);
}

static void
ssl_info_default(const SSL *s, const char *str, int rv)
{
	char *err = sp_printf("%s:error in %s", str, 
	                       CALL_ABI(SSL_state_string_long)(s));

	const char *desc = ssl_get_value_desc(s, rv);
	debug("msg:%s %s", err, desc);
}

static void
ssl_info_error(const SSL *s, const char *str, int rv)
{
	switch(CALL_ABI(SSL_get_error)(s, rv)) {
	case SSL_ERROR_WANT_READ:
	case SSL_ERROR_WANT_WRITE:
	break;
	default:
		ssl_info_default(s, str, rv);
	break;
	}
}

static inline const char *
ssl_state_str(int w)
{
	return (w & SSL_ST_CONNECT)     ? "connect" :
	       (w & SSL_ST_ACCEPT)      ? "accept"  :
	       (w & SSL_ST_INIT)        ? "init" :
	       (w & SSL_ST_BEFORE)      ? "before" :
	       (w & SSL_ST_OK)          ? "ok" :
	       (w & SSL_ST_RENEGOTIATE) ? "renegotiate" : "negotiate";
}

void
ssl_info(const SSL *s, int where, int ret)
{
	struct ssl_sess *ssl_sess = SSL_SESS_GET(s); 
        int w = where & ~SSL_ST_MASK, rv = ret;
	const char *str = ssl_state_str(w);

	if (where & SSL_CB_HANDSHAKE_DONE) {
		ssl_info_state(s, str);
		goto next;
	}

        if (where & SSL_CB_LOOP) {
		ssl_info_state(s, str);
		goto next;
	} else if (where & SSL_CB_ALERT) {
		ssl_info_alert(where, rv);
		goto next;
	} else if (where & SSL_CB_EXIT) {
		if (rv == 0) {
			ssl_info_failed(s, str, rv);
			goto next;
		} else if (rv < 0)
			ssl_info_error(s, str, rv);
	}

next:	
/*
	if (where & SSL_CB_HANDSHAKE_DONE)
		openssl_handshake_handler(s);
*/
	if (ssl_sess->cb.cb_info)
		ssl_sess->cb.cb_info(s, where, ret);
	else if (ssl_sess->ssl_ctxt->cb.cb_info)
		ssl_sess->ssl_ctxt->cb.cb_info(s, where, ret);
}

long
DEFINE_ABI_CALL(SSLeay)(void)
{
	return CALL_ABI(SSLeay)();
}

void
DEFINE_ABI_CALL(SSL_CTX_set_msg_callback)(SSL_CTX *ctx, ssl_cb_msg msg)
{
	struct ssl_ctxt *ssl_ctxt = SSL_CTXT_GET(ctx);
	ssl_ctxt->cb.cb_msg = msg;
	debug("ctx=%p", ctx);
}

void
DEFINE_ABI_CALL(SSL_CTX_set_info_callback)(SSL_CTX *ctx, ssl_cb_info cb)
{
	struct ssl_ctxt *ssl_ctxt = SSL_CTXT_GET(ctx);
	ssl_ctxt->cb.cb_info = cb;
	debug("ctx=%p", ctx);
}

void
DEFINE_ABI_CALL(SSL_set_msg_callback)(SSL *ssl, ssl_cb_msg msg)
{
	struct ssl_sess *ssl_sess = SSL_SESS_GET(ssl);
	ssl_sess->cb.cb_msg = msg;
	debug("ssl=%p", ssl);
}

void
DEFINE_ABI_CALL(SSL_set_info_callback)(SSL *ssl, ssl_cb_info cb)
{
	struct ssl_sess *ssl_sess = SSL_SESS_GET(ssl);
	ssl_sess->cb.cb_info = cb;
	debug("ssl=%p", ssl);
}

long
DEFINE_ABI_CALL(SSL_callback_ctrl)(SSL *ssl, int cmd, void (*fp)(void))
{
	struct ssl_sess *ssl_sess = SSL_SESS_GET(ssl);
	debug("ssl=%p", ssl);

	switch (cmd) {
	case SSL_CTRL_SET_TLSEXT_DEBUG_CB:
		debug("SSL_CTRL_SET_TLSEXT_DEBUG_CB");
		ssl_sess->cb.cb_ext = (typeof(ssl_sess->cb.cb_ext))fp;
		break;
	default:
		debug("cmd=%d", cmd);
		return CALL_ABI(SSL_callback_ctrl)(ssl, cmd, fp);
	}
	return 0;
}

long
DEFINE_ABI_CALL(SSL_CTX_callback_ctrl)(SSL_CTX *ctx, int cmd, void (*fp)(void))
{
	struct ssl_ctxt *ssl_ctxt = SSL_CTXT_GET(ctx);
	debug("ctx=%p", ctx);

	switch (cmd) {
	case SSL_CTRL_SET_TLSEXT_DEBUG_CB:
		debug("SSL_CTRL_SET_TLSEXT_DEBUG_CB");
		ssl_ctxt->cb.cb_ext = (typeof(ssl_ctxt->cb.cb_ext))fp;
		break;
	default:
		debug("cmd=%d", cmd);
		return CALL_ABI(SSL_CTX_callback_ctrl)(ctx, cmd, fp);
	}
	return 0;
}

int
DEFINE_ABI_CALL(SSL_CTX_set_ex_data)(SSL_CTX *ctx, int index, void *data)
{
	return CALL_ABI(SSL_CTX_set_ex_data)(ctx, index + 1, data);
}

void *
DEFINE_ABI_CALL(SSL_CTX_get_ex_data)(const SSL_CTX *ctx, int index)
{
	return CALL_ABI(SSL_CTX_get_ex_data)(ctx, index + 1);
}

int
DEFINE_ABI_CALL(SSL_set_ex_data)(SSL *ssl, int index, void *data)
{
	return CALL_ABI(SSL_set_ex_data)(ssl, index + 1, data);
}

void *
DEFINE_ABI_CALL(SSL_get_ex_data)(const SSL *ssl, int index)
{
	return CALL_ABI(SSL_get_ex_data)(ssl, index + 1);
}

SSL_CTX *
DEFINE_ABI_CALL(SSL_CTX_new)(const SSL_METHOD *method)
{
	SSL_CTX *ctx = CALL_ABI(SSL_CTX_new)(method);

	debug("method=%p", method);

	ssl_version();

	struct ssl_ctxt *ssl_ctxt = malloc(sizeof(*ssl_ctxt));
	CALL_ABI(SSL_CTX_set_ex_data)(ctx, 0, ssl_ctxt);
	memset(ssl_ctxt, 0, sizeof(*ssl_ctxt));

	CALL_ABI(SSL_CTX_set_info_callback)(ctx, ssl_info);

	ssl_ctxt->aaa.authority = getenv("OPENAAA_AUTHORITY");

	if (!EXISTS_ABI(SSL_CTX_add_client_custom_ext))
		return ctx;
	if (!EXISTS_ABI(SSL_CTX_add_server_custom_ext))
		return ctx;

	CALL_ABI(SSL_CTX_add_client_custom_ext)(ctx, TLS_EXT_SUPPLEMENTAL_DATA, 
	                                  ssl_ext_cli_add, NULL, NULL,
	                                  ssl_ext_cli_parse, NULL);
	CALL_ABI(SSL_CTX_add_server_custom_ext)(ctx, TLS_EXT_SUPPLEMENTAL_DATA,
	                                  ssl_ext_srv_add, NULL, NULL, 
	                                  ssl_ext_srv_parse, NULL);
	return ctx;
}

void
DEFINE_ABI_CALL(SSL_CTX_free)(SSL_CTX *ctx)
{
	struct ssl_ctxt *ssl_ctxt = SSL_CTXT_GET(ctx);
	free(ssl_ctxt);
	debug("ctx=%p", ctx);
	CALL_ABI(SSL_CTX_free)(ctx);
}

SSL *
DEFINE_ABI_CALL(SSL_new)(SSL_CTX *ctx)
{
	SSL *ssl = CALL_ABI(SSL_new)(ctx);

	struct ssl_sess *ssl_sess = malloc(sizeof(*ssl_sess));
	CALL_ABI(SSL_set_ex_data)(ssl, 0, ssl_sess);
	memset(ssl_sess, 0, sizeof(*ssl_sess));

	struct ssl_ctxt *ssl_ctxt = SSL_CTXT_GET(ctx);
	ssl_sess->ssl_ctxt = ssl_ctxt;
	ssl_sess->ctx = ctx;
	ssl_sess->ssl = ssl;

	CALL_ABI(SSL_callback_ctrl)(ssl, SSL_CTRL_SET_TLSEXT_DEBUG_CB, 
	                            (void (*)(void))ssl_extension);

	CALL_ABI(SSL_set_info_callback)(ssl, ssl_info);

	debug("ssl=%p ctx=%p", ssl, ctx);
	return ssl;
}

void
DEFINE_ABI_CALL(SSL_free)(SSL *ssl)
{
	struct ssl_sess *ssl_sess = SSL_SESS_GET(ssl);
	if (ssl_sess->aaa.authority)
		free(ssl_sess->aaa.authority);
	free(ssl_sess);
	debug("ssl = %p", ssl);
	return CALL_ABI(SSL_free)(ssl);
}

void
crypto_lookup(void)
{
	
	IMPORT_ABI(SSLeay);
	IMPORT_ABI(SSL_CTX_new);
	IMPORT_ABI(SSL_CTX_free);
	IMPORT_ABI(SSL_CTX_callback_ctrl);
	IMPORT_ABI(SSL_CTX_set_ex_data);
	IMPORT_ABI(SSL_CTX_get_ex_data);
	IMPORT_ABI(SSL_CTX_add_client_custom_ext);
	IMPORT_ABI(SSL_CTX_add_server_custom_ext);
	IMPORT_ABI(SSL_new);
	IMPORT_ABI(SSL_free);
	IMPORT_ABI(SSL_callback_ctrl);
	IMPORT_ABI(SSL_set_ex_data);
	IMPORT_ABI(SSL_get_ex_data);
	IMPORT_ABI(SSL_CTX_set_msg_callback);
	IMPORT_ABI(SSL_CTX_set_info_callback);
	IMPORT_ABI(SSL_set_msg_callback);
	IMPORT_ABI(SSL_set_info_callback);
	IMPORT_ABI(SSL_export_keying_material);
	IMPORT_ABI(SSL_state_string);
	IMPORT_ABI(SSL_state_string_long);
	IMPORT_ABI(SSL_alert_type_string);
	IMPORT_ABI(SSL_alert_type_string_long);
	IMPORT_ABI(SSL_alert_desc_string);
	IMPORT_ABI(SSL_alert_desc_string_long);
	IMPORT_ABI(SSL_get_error);
	IMPORT_ABI(SSL_get_session);
	IMPORT_ABI(SSL_SESSION_free);
	IMPORT_ABI(SSL_SESSION_get_id);
	IMPORT_ABI(SSL_SESSION_print);
	IMPORT_ABI(BIO_new);
	IMPORT_ABI(BIO_free);
	IMPORT_ABI(BIO_s_mem);
	IMPORT_ABI(BIO_ctrl);
	IMPORT_ABI(BIO_read);
	IMPORT_ABI(X509_NAME_oneline);
	IMPORT_ABI(SSL_get_ex_data_X509_STORE_CTX_idx);
	IMPORT_ABI(X509_STORE_CTX_get_ex_data);
	IMPORT_ABI(SSL_get_peer_certificate);
	IMPORT_ABI(SSL_get_certificate);
	IMPORT_ABI(SSL_get_SSL_CTX);
	IMPORT_ABI(SSL_CTX_get_cert_store);
	IMPORT_ABI(SSL_extension_supported);

	plthook_t *plt;
	plthook_open(&plt, NULL);
	if (!plt)
		return;

	UPDATE_ABI(SSLeay);
	UPDATE_ABI(SSL_CTX_new);
	UPDATE_ABI(SSL_CTX_free);
	UPDATE_ABI(SSL_CTX_callback_ctrl);
	UPDATE_ABI(SSL_CTX_set_ex_data);
	UPDATE_ABI(SSL_CTX_get_ex_data);
	UPDATE_ABI(SSL_new);
	UPDATE_ABI(SSL_free);
	UPDATE_ABI(SSL_callback_ctrl);
	UPDATE_ABI(SSL_CTX_set_msg_callback);
	UPDATE_ABI(SSL_CTX_set_info_callback);
	UPDATE_ABI(SSL_set_msg_callback);
	UPDATE_ABI(SSL_set_info_callback);

	plthook_close(plt);
}
