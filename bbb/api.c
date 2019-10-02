#include <sys/compiler.h>
#include <sys/cpu.h>
#include <sys/log.h>
#include <mem/pool.h>
#include <bbb/lib.h>
#include <bbb/prv.h>
#include <list.h>
#include <dict.h>
#include <buffer.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/bio.h>
#include <openssl/tls1.h>
#include <openssl/x509.h>

#include <crypto/hex.h>
#include <crypto/sha1.h>
#include <net/tls/ext.h>

#include <aaa/lib.h>
#include <aaa/prv.h>

#include <nghttp2/nghttp2.h>
#define AAA_ATTR_AUTHORITY 1
#define AAA_ATTR_PROTOCOL  2
#define AAA_ATTR_VERSION   3

static const char *aaa_attr_names[] = {
	[AAA_ATTR_AUTHORITY] = "aaa.authority",
	[AAA_ATTR_PROTOCOL]  = "aaa.protocol",
	[AAA_ATTR_VERSION]   = "aaa.version"
};

char aaa_sess_id[255] = {0};
char aaa_bind_id[255] = {0};
char aaa_bind_key[255] = {0};
char aaa_authority[255] = {0};

enum { IO_NONE, WANT_READ, WANT_WRITE };
#define MAKE_NV(NAME, VALUE) \
{ \
	(u8 *)NAME, (u8 *)VALUE, sizeof(NAME) - 1, sizeof(VALUE) - 1, \
	NGHTTP2_NV_FLAG_NONE \
}

#define MAKE_NV_CS(NAME, VALUE) \
{ \
	(u8 *)NAME, (u8 *)VALUE, sizeof(NAME) - 1, strlen(VALUE), \
	NGHTTP2_NV_FLAG_NONE  \
}

static int http2_initialized = 0;

struct connection {
	SSL *ssl;
	nghttp2_session *sess;
	int wio;
};

struct request {
	char *host;
	char *path;
	char *hostport;
	s32 stream_id;
	u16 port;
};

struct uri {
	const char *host;
	const char *path;
	size_t pathlen;
	const char *hostport;
	size_t hostlen;
	size_t hostportlen;
	uint16_t port;
};

static char *
strcopy(const char *s, size_t len) 
{
	char *dst = malloc(len + 1);
	memcpy(dst, s, len);
	dst[len] = '\0';
	return dst;
}

#define SSL_USER_IDX 666
#define SSL_SESS_SET(ssl, data) \
	SSL_set_ex_data(ssl, SSL_USER_IDX, data)
#define SSL_SESS_GET(ssl) \
	(struct session *)SSL_get_ex_data(ssl, SSL_USER_IDX)

struct cf_tls_rfc5705 {
	char *context;
	char *label;
	unsigned int length;
};

static struct cf_tls_rfc5705 cf_tls_rfc5705 = {
	.context = "OpenAAA",
	.label   = "EXPORTER_AAA",
	.length  = 16
};


typedef void
(*ssl_cb_ext)(const SSL *ssl, int c, int type, byte *data, int len, void *arg);
typedef void
(*ssl_cb_info)(const SSL *s, int where, int ret);

enum ssl_endpoint_type {
	TLS_EP_PEER   = 0,
	TLS_EP_CLIENT = 1,
	TLS_EP_SERVER = 2	
};

struct ssl_cb {
	ssl_cb_info cb_info;
	ssl_cb_ext cb_ext;
} ssl_cb;

struct list ssl_module_list;

struct ssl_module {
	struct node node;
	char *file;
	void *dll;
};

struct ssl_aaa {
	char *authority;
	char *protocol;
	char *handler;
	char *group;
	char *role;
	int verbose;
};

struct ssl_aaa aaa;

struct aaa_keys {
	struct bb binding_key;
	struct bb binding_id;
};

struct session {
	struct mm_pool *mp;
	struct dict recved;
	struct dict posted;
	struct aaa_keys keys;
	SSL_CTX *ctx;
	SSL *ssl;
	X509 *cert;
	char *tls_binding_key;
	char *aaa_binding_key;
	enum ssl_endpoint_type endpoint;
};

static int server_handshake_synch = 1;
static int server_always          = 0;

static int ssl_sca_enabled = 1;

void
__ssl_info(const SSL *s, int where, int ret);

static void
__ssl_handshake0(const SSL *ssl);

static inline const char *
__ssl_endpoint_str(int type)
{
	return type == TLS_EP_CLIENT ? "client":
	       type == TLS_EP_SERVER ? "server": "undefined";
}

static void
__ssl_extensions(SSL *ssl, int c, int type, byte *data, int len, void *arg)
{ 
	struct session *sp = SSL_SESS_GET(ssl);
	sp->endpoint = c ? TLS_EP_CLIENT : TLS_EP_SERVER;

	info("extension name=%s type=%d, len=%d endpoint=%d", 
	       tls_strext(type), type, len, sp->endpoint);

	ssl_cb.cb_ext ? ssl_cb.cb_ext(ssl, c, type, data, len, arg):({});
}

void
__ssl_callbacks(const SSL *ssl)
{
	void (*fn)(void) = (void (*)(void))SSL_get_info_callback(ssl);
	if (!fn)
		goto done;

	if (fn != (void (*)(void))__ssl_info)
		ssl_cb.cb_info = (void (*)(const SSL *, int, int))fn;
	else
		return;

done:
	fn = (void (*)(void))__ssl_extensions;
	SSL_set_info_callback((SSL *)ssl, __ssl_info);
}

static struct session *
__session_init(const SSL *ssl)
{
	struct mm_pool *mp = mm_pool_create(CPU_PAGE_SIZE, 0);
	struct session *sp = mm_pool_zalloc(mp, sizeof(*sp));

	dict_init(&sp->recved, mm_pool(mp));
	dict_init(&sp->posted, mm_pool(mp));

	sp->mp = mp;
	sp->ssl = (SSL *)ssl;
	__ssl_callbacks(ssl);

	SSL_SESS_SET((SSL *)ssl, sp);
	return sp;
}

static void
__session_fini(struct session *sp)
{
	SSL *ssl = sp->ssl;
	SSL_SESS_SET(ssl, NULL);
	mm_pool_destroy(sp->mp);
}

static struct session *
__session_get0(const SSL *ssl)
{
	struct session *sp = SSL_SESS_GET((SSL *)ssl);
	return sp ? sp : __session_init((SSL *)ssl);
}

static inline int
__export_keying_material(struct session *sp)
{
	SSL *s = sp->ssl;

	char *lab = cf_tls_rfc5705.label;
	size_t len = strlen(lab);
	size_t sz = cf_tls_rfc5705.length;

	sp->keys.binding_key.len = 0;
	char *key = sp->keys.binding_key.addr = mm_pool_zalloc(sp->mp, sz + 1);
        if (!SSL_export_keying_material(s, key, sz, lab, len, NULL,0,0))
		return 1;

	sp->keys.binding_key.len = sz;
	return 0;
}

static void
__ssl_exportkeys(struct session *sp)
{
	char *bind_key, *bind_id, *sess_id;
	struct aaa_keys *a = &sp->keys;

	if (!a->binding_key.len || !a->binding_id.len)
		return;

	SSL_SESSION *sess = SSL_get_session(sp->ssl);
	unsigned int len;
	const byte *id = SSL_SESSION_get_id(sess, &len);
	
	bind_key = evala(memhex, a->binding_key.addr, a->binding_key.len);
	debug3("tls_binding_key=%s", bind_key);
	bind_id = evala(memhex, a->binding_id.addr, a->binding_id.len);
	debug3("tls_binding_id=%s", bind_id);
	sess_id = evala(memhex, (char *)id, len);

	/* tls_session_id is empty for tls tickets for client */
	/* this is hack for no_session_id cases (vpn) */
	if (sess_id && *sess_id)
		debug3("tls_session_id=%s", sess_id);
	else
		sess_id = bind_key;

	//snprintf(aaa_authority, sizeof(aaa_authority), "%s", authority);
	snprintf(aaa_sess_id, sizeof(aaa_sess_id), "%s", sess_id);
	snprintf(aaa_bind_id, sizeof(aaa_bind_id), "%s", bind_id);
	snprintf(aaa_bind_key, sizeof(aaa_bind_key), "%s", bind_key);

	if (sp->endpoint == TLS_EP_SERVER || server_always) {
		struct aaa *usr = aaa_new(AAA_ENDPOINT_SERVER, 0);
		aaa_attr_set(usr, "sess.id", sess_id);
		aaa_attr_set(usr, "sess.key",bind_key);
		aaa_bind(usr);
		aaa_free(usr);
	}
}

static int
__ssl_derive_keys(struct session *sp)
{
	char *key;
	struct aaa_keys *a = &sp->keys;

	if (__export_keying_material(sp))
		return -EINVAL;

	struct sha1 sha1;
	sha1_init(&sha1);

#define OPENAAA_COMPAT 1
#ifdef  OPENAAA_COMPAT
	key = evala(memhex, a->binding_key.addr, a->binding_key.len);
	sha1_update(&sha1, key, strlen(key));
#else
	sha1_update(&sha1, a->binding_key.addr, a->binding_key.len);
#endif
	key = sha1_final(&sha1);

	a->binding_id.addr = mm_pool_alloc(sp->mp, SHA1_SIZE);
	memcpy(a->binding_id.addr, key, SHA1_SIZE / 2);
	a->binding_id.len  = SHA1_SIZE / 2;

	__ssl_exportkeys(sp);

	return 0;
}

static inline int
__ssl_attr_value(struct session *sp, int type, char *str)
{
	dict_set(&sp->recved, aaa_attr_names[type], str);
	debug3("%s: %s", aaa_attr_names[type], str);
	return 0;
}

static inline int
__ssl_parse_attr(struct session *sp, char *line, size_t size)
{
	char *s = strchr(line,'=');
	if (!s || !*s)
		return -EINVAL;

	char *p = line + size;
	char *v = s + 1; *p = *s = 0;

	for (int i = 1; i < array_size(aaa_attr_names); i++) {
		if (strncmp(aaa_attr_names[i], line, strlen(aaa_attr_names[i])))
			continue;
		if (__ssl_attr_value(sp, i, v))
			return -EINVAL;
		return 0;
	}

	return -EINVAL;
}

static inline int
__ssl_attr_lookup(char *line, size_t size, int state)
{
	for (int i = 1; i < array_size(aaa_attr_names); i++)
		if (!strncmp(aaa_attr_names[i], line, size))
			return i;
	return state;
}

static char *
__next_attr(char *line, size_t size)
{
	char *p = line;
	while (size) {
		if (!*p && p == line)
			return NULL;
		if (!*p || *p == '\n')
			return p;
		p++; size--;
	}
	return p;
}

static inline int
__ssl_parse_attrs(struct session *sp, char *line, size_t size)
{
	int cursor = 0;
	for(char *p = __next_attr(line, size); p; p = __next_attr(line, size)) {
		int state = __ssl_attr_lookup(line, p - line, cursor);
		if (state == cursor) 
			__ssl_parse_attr(sp, line, p - line);

		line = p + 1;
		cursor = state;
	}

	return 0;
}

static int
__ssl_server_add(SSL *s, uint type, const byte **out, size_t *len, int *al, void *arg)
{
	struct session *sp = __session_get0(s);
	struct mm_pool *mp = sp ? sp->mp : NULL;

	sp->endpoint = TLS_EP_SERVER;

	if (!ssl_sca_enabled)
		return 0;

	dict_set(&sp->posted, "aaa.authority", aaa.authority);
	dict_set(&sp->posted, "aaa.protocol",  "aaa");
	dict_set(&sp->posted, "aaa.version",   "1.0");

	char bb[8192];
	unsigned int sz = 0;
	dict_for_each(attr, sp->posted.list) {
		sz += snprintf(bb, sizeof(bb) - sz - 1, "%s=%s\n",attr->key, attr->val);
	}

	char *b = mm_pool_alloc(mp, sz + 1);
	*len = sz + 1;
	sz = 0;
	dict_for_each(attr, sp->posted.list) {
		debug("extension %s=%s", attr->key, attr->val);
		sz += snprintf(b + sz, *len, "%s=%s\n",attr->key, attr->val);
	}

	b[sz] = 0;
	debug("extension name=%s type=%d send",tls_strext(type), type);
	*out = b;
	return 1;
}

int
__ssl_server_get(SSL *s, uint type, const byte*in, size_t len, int *l, void *a)
{
	struct session *sp = __session_get0(s);
	info("extension name=%s type=%d recv", tls_strext(type), type);
	if (len && (type == TLS_EXT_SUPPLEMENTAL_DATA))
		__ssl_parse_attrs(sp, (char *)in, len);

	return 1;
}

static int
__ssl_client_add(SSL *s, unsigned int type, const byte **out, size_t *len, 
               int *al, void *arg)
{
	struct session *sp = __session_get0(s);
	struct mm_pool *mp = sp ? sp->mp : NULL;

	sp->endpoint = TLS_EP_CLIENT;
	if (!ssl_sca_enabled)
		return 0;

	dict_set(&sp->recved, "aaa.protocol", "aaa");
	dict_set(&sp->recved, "aaa.version",  "1.0");

	char bb[8192];
	unsigned int sz = 0;
	dict_for_each(a, sp->recved.list) {
		sz += snprintf(bb + sz, sizeof(bb) - sz, "%s=%s\n",a->key, a->val);
	}

	char *b = mm_pool_alloc(mp, sz + 1);
	*len = sz + 1;
	sz = 0;
	dict_for_each(attr, sp->recved.list) {
		debug("extension %s=%s", attr->key, attr->val);
		sz += snprintf(b + sz, *len, "%s=%s\n",attr->key, attr->val);
	}

	b[sz] = 0;
	debug("extension name=%s type=%d send ",tls_strext(type), type);

	*out = b;
	return 1;
}

int
__ssl_client_get(SSL *ssl, unsigned int type, const byte *in, size_t len, 
                 int *al, void *arg)
{
	struct session *sp = __session_get0(ssl);
	info("extension name=%s type=%d recv", tls_strext(type), type);

	if (len && (type == TLS_EXT_SUPPLEMENTAL_DATA))
		__ssl_parse_attrs(sp, (char *)in, len);

	return 1;
}

/*
static inline void
pubkey_fixups(char *str, unsigned int len)
{
	char *p = str;
	for (unsigned int i = 0; i < len && *p; i++, p++)
		if (*p == '\r' || *p == ' ' || *p == '\t')
			continue;
		else
			*str++ = *p;
	*str = 0;
}

static void x509_fingerprint(void)
{
	int j;                                                          
	unsigned int n;                                                 
	unsigned char md[EVP_MAX_MD_SIZE];                              
	const EVP_MD *fdig = digest;                                    
	if (!fdig)                                                      
	fdig = EVP_sha1();                                          
	if (!X509_digest(x, fdig, md, &n)) {                            
	BIO_printf(bio_err, "out of memory\n");                     
	goto end;                                                   
	}                                                               
	BIO_printf(out, "%s Fingerprint=",                              
	OBJ_nid2sn(EVP_MD_type(fdig)));                      
	for (j = 0; j < (int)n; j++) {                                  
		BIO_printf(out, "%02X%c", md[j], (j + 1 == (int)n)          
		? '\n' : ':');                                   
	}
}

static inline void
pubkey_derive_key(struct session *sp, X509 *x)
{
	byte pub[8192];
        EVP_PKEY *key = sym_X509_get_pubkey(x);
        if (!key)
		return;

	int size = sym_EVP_PKEY_size(key);
	int bits = sym_EVP_PKEY_bits(key);

	BIO *bio = sym_BIO_new(sym_BIO_s_mem());
	sym_PEM_write_bio_PUBKEY(bio, key);

	BUF_MEM *bptr;
	sym_BIO_ctrl(bio, BIO_C_GET_BUF_MEM_PTR, 0,(char *)&bptr);

	if (bptr->length > (sizeof(pub) - 1))
		goto cleanup;

	memcpy(pub, bptr->data, bptr->length);
	pub[bptr->length] = 0;

	pubkey_fixups((char *)pub, bptr->length);
	int hash = hash_string((char *)pub);

        sha1_context sha1;
        sha1_init(&sha1);
        sha1_update(&sha1, (byte *)pub, bptr->length);
        sha1_update(&sha1, (byte *)tls->key, tls->key_size);

        memcpy(tls->sec, (char *)sha1_final(&sha1), SHA1_SIZE);
	tls->sec_size = SHA1_SIZE;
        char *sec = stk_mem_to_hex(tls->sec, SHA1_SIZE);	

	debug("checking for server public key: len=%d size=%d bits=%d hash=%d", 
	        bptr->length, size, bits, hash);

	debug("checking for derived binding key: aaa_binding_key=%s", sec);

cleanup:
	sym_BIO_free(bio);
	sym_EVP_PKEY_free(key);
}
*/

/*
static int
ssl_setsession(struct session *sp)
{
	SSL_SESSION *sess = CALL_ABI(SSL_get_session)(sp->ssl);
	unsigned int len;
	const byte *id = CALL_ABI(SSL_SESSION_get_id)(sess, &len);
	char *key = evala(memhex, (char *)id, len);

	struct aaa *aaa = aaa_new(AAA_ENDPOINT_SERVER, 0);
	aaa_attr_set(aaa, "sess.id", key);
	aaa_bind(aaa, 0, key);

	aaa_free(aaa);

	return 0;
}
*/

static int
__ssl_server_aaa(struct session *sp)
{
	struct aaa_keys *a = &sp->keys;
	char *key = evala(memhex, a->binding_key.addr, a->binding_key.len);
	char *id  = evala(memhex, a->binding_id.addr, a->binding_id.len);

	const char *proto_attr   = aaa_attr_names[AAA_ATTR_PROTOCOL];
	const char *proto_client = dict_get(&sp->recved, proto_attr);
	const char *proto_server = aaa.protocol;

	SSL_SESSION *sess = SSL_get_session(sp->ssl);
	unsigned int len;
	const byte *sessid = SSL_SESSION_get_id(sess, &len);
	char *sess_id = evala(memhex, (char *)sessid, len);

	long timeout = SSL_SESSION_get_timeout(sess);
	info("ssl.timeout: %ld", timeout);

	struct aaa *usr = aaa_new(AAA_ENDPOINT_SERVER, 0);

	if (!sess_id || !*sess_id)
		sess_id = key;

	info("aaa.authority=%s", aaa.authority);
	info("aaa.handler=%s", aaa.handler);

	info("protocol server=%s client=%s", proto_server, proto_client);

	aaa_attr_set(usr, "sess.id", sess_id);
	aaa_attr_set(usr, "sess.key", key);
	aaa_bind(usr);
	aaa_free(usr);

	if (!proto_client || !proto_server)
		return -EINVAL;
	if (strcmp(proto_client, proto_server))
		return -EINVAL;
	if (!aaa.handler || !key || !id || !aaa.authority)
		return -EINVAL;

//	ssl_setsession(sp);
//
	info("handshake_synch=%s",  server_handshake_synch ? "yes": "no");

	char *synch = "";
#ifdef CONFIG_LINUX	
	synch = server_handshake_synch ? "" : "&";
#endif
	char *host = aaa.authority;
	char *msg;
	if (aaa.group && aaa.role)
		msg = printfa("%s -pri -a%s -i%s -k%s -g%s -r%s", 
		         aaa.handler, host, id, key, aaa.group, aaa.role);
	else
		msg = printfa("%s -pri -a%s -i%s -k%s", 
		              aaa.handler, host, id, key);
	
	_unused int status = system(msg);
	debug("%s", WEXITSTATUS(status)? "failed" : "channel binding");

	if (aaa.group && aaa.role)
		msg = printfa("%s -pr4 -s%s -a%s -i%s -k%s -g%s -r%s %s", 
		         aaa.handler, sess_id, host, id, key, aaa.group, aaa.role, synch);
	else
		msg = printfa("%s -pr4 -s%s -a%s -i%s -k%s %s", 
		              aaa.handler, sess_id, host, id, key, synch);

	debug("cmd=%s", msg);
	
	status = system(msg);

	if (!server_handshake_synch)
		debug("%s", WEXITSTATUS(status)? "forbidden" : "authenticated");

	if (!server_handshake_synch)
		return 0;

	SSL_set_verify_result(sp->ssl, X509_V_ERR_APPLICATION_VERIFICATION);
	SSL_shutdown(sp->ssl);
	return X509_V_ERR_APPLICATION_VERIFICATION;
}

static int
__ssl_client_aaa(struct session *sp)
{
	const char *authority = dict_get(&sp->recved, "aaa.authority");

	struct aaa_keys *a = &sp->keys;
	char *key = evala(memhex, a->binding_key.addr, a->binding_key.len);
	char *id  = evala(memhex, a->binding_id.addr,  a->binding_id.len);

	authority = authority ? authority : aaa.authority;
	debug4("authority=%s", authority);
	debug4("handler=%s", aaa.handler);

	snprintf(aaa_authority, sizeof(aaa_authority), "%s", authority);

	if (!aaa.handler || !key || !id || !authority)
		return -EINVAL;

#ifdef CONFIG_WIN32
	const char *pre = "START /B ", *end = "";
	const char *msg = printfa("%s %s -k%s -i%s -prx -a%s %s", 
	                          pre, aaa.handler, key, id, authority, end);

#else
	const char *pre = "", *end = "&";
	const char *msg = printfa("%s%s -k%s -i%s -prx -a%s %s", 
	                          pre, aaa.handler, key, id, authority, end);
#endif
	_unused int status = system(msg);
	return WEXITSTATUS(status);
}

static void
__ssl_handshake0(const SSL *ssl)
{

}

/* TLS Handshake phaze 1 */
static void
__ssl_handshake1(const SSL *ssl)
{
	struct session *sp = SSL_SESS_GET(ssl);
	const char *endpoint = __ssl_endpoint_str(sp->endpoint);
	X509_NAME *x_subject, *x_issuer;
	char *subject = NULL, *issuer = NULL;

	if (sp->endpoint == TLS_EP_SERVER) 
		sp->cert = SSL_get_certificate((SSL *)ssl);
	else if (sp->endpoint == TLS_EP_CLIENT)
		sp->cert = SSL_get_peer_certificate((SSL *)ssl);
	else goto cleanup;

	info("%s checking for server certificate: %s", 
	      endpoint, sp->cert ? "Yes" : "No");
	if (!sp->cert)
		goto cleanup;

	x_subject = X509_get_subject_name(sp->cert);
	x_issuer  = X509_get_issuer_name(sp->cert);
	subject   = X509_NAME_oneline(x_subject, NULL, 0);
	issuer    = X509_NAME_oneline(x_issuer,  NULL, 0);

	info("checking for subject: %s", subject);
	info("checking for issuer:  %s", issuer);

	if (!ssl_sca_enabled)
		return;

	__ssl_derive_keys(sp);

	const unsigned char *alpn = NULL;
	unsigned int size = 0;
	SSL_get0_alpn_selected(ssl, &alpn, &size);

	if (sp->endpoint)
		info("%s checking for application-layer protocol negotiation: %s",
		       endpoint, size ? strmema(alpn, size) : "No");

	if (sp->endpoint == TLS_EP_SERVER) 
		__ssl_server_aaa(sp);
	else if (sp->endpoint == TLS_EP_CLIENT)
		__ssl_client_aaa(sp);

cleanup:
/*
	if (subject)
		CRYPTO_free(subject);
	if (issuer)
		CRYPTO_free(issuer);
*/
	__session_fini(sp);
}


static const char *
__ssl_get_value_desc(const SSL *s, int code)
{
	return NULL;
}

static void
__ssl_info_state(const SSL *s, const char *str)
{
	const char *state = SSL_state_string_long(s);
	char *d = printfa("%s:%s", str, state);
	info("msg:%s", d);
}

static void
__ssl_info_alert(int where, int rv)
{
	const char *type = SSL_alert_type_string_long(rv);
	const char *desc = SSL_alert_desc_string_long(rv);

	char *v = printfa("alert %s:%s:%s", (where & SSL_CB_READ) ?
	                    "read" : "write", type, desc);
	info("msg:%s", v);
}

static void
__ssl_info_failed(const SSL *s, const char *str, int rv)
{
	char *err = printfa("%s:failed in %s", str, SSL_state_string_long(s));
	const char *desc = __ssl_get_value_desc(s, rv);
	info("msg:%s %s", err, desc);
}

static void
__ssl_info_default(const SSL *s, const char *str, int rv)
{
	char *e = printfa("%s:error in %s", str, SSL_state_string_long(s));
	const char *desc = __ssl_get_value_desc(s, rv);
	info("msg:%s %s", e, desc);
}

static void
__ssl_info_error(const SSL *s, const char *str, int rv)
{
	switch(SSL_get_error(s, rv)) {
	case SSL_ERROR_WANT_READ:
		break;
	case SSL_ERROR_WANT_WRITE:
		break;
	default:
		__ssl_info_default(s, str, rv);
		break;
	}
}


static inline const char *
__ssl_state_str(int w)
{
	return (w & SSL_ST_CONNECT) ? "connect" :
	       (w & SSL_ST_ACCEPT)  ? "accept":"handshake";
}

void
__ssl_info(const SSL *s, int where, int ret)
{
	struct session *sp = __session_get0(s);

        int w = where & ~SSL_ST_MASK, rv = ret;
	const char *str = __ssl_state_str(w);

	if (where & SSL_CB_HANDSHAKE_DONE) {
		__ssl_info_state(s, str);
	}
        if (where & SSL_CB_LOOP) {
		__ssl_info_state(s, str);
	} else if (where & SSL_CB_ALERT) {
		__ssl_info_alert(where, rv);
	} else if (where & SSL_CB_EXIT) {
		if (rv == 0) {
			__ssl_info_failed(s, str, rv);
		} else if (rv < 0)
			__ssl_info_error(s, str, rv);
	}

	if ((where & SSL_CB_HANDSHAKE_START) && sp)
		__ssl_handshake0(s);
	if (where & SSL_CB_HANDSHAKE_DONE)
		__ssl_handshake1(s);

	if (ssl_cb.cb_info)
		ssl_cb.cb_info(s, where, ret);
}

void
__ssl_init_ctxt(SSL_CTX *ctx)
{
	void (*fn)(void) = (void (*)(void))__ssl_extensions;
	SSL_CTX_callback_ctrl(ctx, SSL_CTRL_SET_TLSEXT_DEBUG_CB, fn);
#ifdef SSL_OP_NO_TICKET
	SSL_CTX_ctrl(ctx, 0, SSL_OP_NO_TICKET, NULL);
#endif
	
	SSL_CTX_add_client_custom_ext(ctx, 1000, __ssl_client_add, NULL, NULL,
	                                __ssl_client_get, NULL);
	SSL_CTX_add_server_custom_ext(ctx, 1000, __ssl_server_add, NULL, NULL, 
	                                __ssl_server_get, NULL);
}

void
__ssl_init_conn(SSL *ssl)
{
	_unused struct session *sp = __session_get0(ssl);
#ifdef SSL_OP_NO_TICKET
	SSL_ctrl(ssl, 0, SSL_OP_NO_TICKET, NULL);
#endif
	
}

static ssize_t
on_send(nghttp2_session *sess, const u8 *u8, size_t len, int flags, void *user) 
{
	struct connection *connection = (struct connection *)user;
	connection->wio = IO_NONE;
	ERR_clear_error();
	int rv = SSL_write(connection->ssl, u8, (int)len);
	if (rv <= 0) {
		int err = SSL_get_error(connection->ssl, rv);
		if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
			connection->wio =
			(err == SSL_ERROR_WANT_READ ? WANT_READ : WANT_WRITE);
			rv = NGHTTP2_ERR_WOULDBLOCK;
		} else {
			rv = NGHTTP2_ERR_CALLBACK_FAILURE;
		}
	}
	return rv;
}

static ssize_t 
on_recv(nghttp2_session *session, u8 *buf, size_t len, int flags, void *user) 
{
	struct connection *connection;
	int rv;
	(void)session;
	(void)flags;

	connection = (struct connection *)user;
	connection->wio = IO_NONE;
	ERR_clear_error();
	rv = SSL_read(connection->ssl, buf, (int)len);
	if (rv < 0) {
		int err = SSL_get_error(connection->ssl, rv);
		if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
			connection->wio =
		        (err == SSL_ERROR_WANT_READ ? WANT_READ : WANT_WRITE);
			rv = NGHTTP2_ERR_WOULDBLOCK;
		} else {
			rv = NGHTTP2_ERR_CALLBACK_FAILURE;
		}
	} else if (rv == 0) {
		rv = NGHTTP2_ERR_EOF;
	}
	return rv;
}

static int
on_frame_send(nghttp2_session *sess, const nghttp2_frame *frame, void *user) 
{
        _unused struct http2 *http2 = (struct http2 *)user;

	switch (frame->hd.type) {
	case NGHTTP2_HEADERS:
		if (nghttp2_session_get_stream_user_data(sess, frame->hd.stream_id)) {
			_unused const nghttp2_nv *nva = frame->headers.nva;
			info("C ----------------------------> S (HEADERS)");
	
			for (int i = 0; i < frame->headers.nvlen; ++i) {
				fwrite(nva[i].name, 1, nva[i].namelen, stdout);
			printf(": ");
			fwrite(nva[i].value, 1, nva[i].valuelen, stdout);
			printf("\n");
			}

	}
	break;
	case NGHTTP2_RST_STREAM:
		info("C ----------------------------> S (RST_STREAM)");
		break;
	case NGHTTP2_GOAWAY:
		info("C ----------------------------> S (GOAWAY)");
		break;
	}
	return 0;
}

static int
on_frame_recv(nghttp2_session *sess, const nghttp2_frame *frame, void *user) 
{
        _unused struct http2 *http2 = (struct http2 *)user;
	switch (frame->hd.type) {
	case NGHTTP2_HEADERS:
		if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE) {
			_unused const nghttp2_nv *nva = frame->headers.nva;
			struct request *req;
			req = nghttp2_session_get_stream_user_data(sess, frame->hd.stream_id);
			if (!req) break;
			info("C <---------------------------- S (HEADERS)");
			for (int i = 0; i < frame->headers.nvlen; ++i) {
				fwrite(nva[i].name, 1, nva[i].namelen, stdout);
				printf(": ");
				fwrite(nva[i].value, 1, nva[i].valuelen, stdout);
				printf("\n");
			}
		}
		break;
	case NGHTTP2_RST_STREAM:
		info("C <---------------------------- S (RST_STREAM)");
		break;
	case NGHTTP2_GOAWAY:
		info("C <---------------------------- S (GOAWAY)");
		break;
	}
	return 0;
}

static int
on_stream_close(nghttp2_session *sess, s32 sid, u32 err, void *user) 
{
	struct request *req = nghttp2_session_get_stream_user_data(sess, sid);
	if (req) {
		int rv;
		rv = nghttp2_session_terminate_session(sess, NGHTTP2_NO_ERROR);
		if (rv != 0) {
			info("http2_session_terminate_session");
			return -1;
		}
	}
	return 0;
}

static int
on_chunk_recv(nghttp2_session *sess, u8 flags, s32 sid, const u8 *data,
                   size_t len, void *user) 
{
	struct request *req = nghttp2_session_get_stream_user_data(sess, sid);
	if (req) {
		info("C <---------------------------- S (DATA chunk)"
		"%lu bytes", (unsigned long int)len);
		fwrite(data, 1, len, stdout);
		printf("\n");
	}
	return 0;
}

static void 
setup_nghttp2_callbacks(nghttp2_session_callbacks *c) 
{
	nghttp2_session_callbacks_set_send_callback(c, on_send);
	nghttp2_session_callbacks_set_recv_callback(c, on_recv);
	nghttp2_session_callbacks_set_on_frame_send_callback(c, on_frame_send);
	nghttp2_session_callbacks_set_on_frame_recv_callback(c, on_frame_recv);
	nghttp2_session_callbacks_set_on_stream_close_callback(c, on_stream_close);
	nghttp2_session_callbacks_set_on_data_chunk_recv_callback(c, on_chunk_recv);
}

#ifndef OPENSSL_NO_NEXTPROTONEG
static int
select_next_proto_cb(SSL *ssl, unsigned char **out,
unsigned char *outlen, const unsigned char *in,
unsigned int inlen, void *arg) 
{
	(void)ssl;
	(void)arg;

	int rv = nghttp2_select_next_protocol(out, outlen, in, inlen);
	if (rv <= 0) {
		error("Server did not advertise HTTP/2 protocol");
		return -1;
	}
	return SSL_TLSEXT_ERR_OK;
}
#endif /* !OPENSSL_NO_NEXTPROTONEG */

static void 
init_ssl_ctx(SSL_CTX *ssl_ctx) 
{
	SSL_CTX_set_options(ssl_ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2);
	SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);
	SSL_CTX_set_mode(ssl_ctx, SSL_MODE_RELEASE_BUFFERS);

#ifndef OPENSSL_NO_NEXTPROTONEG
	SSL_CTX_set_next_proto_select_cb(ssl_ctx, select_next_proto_cb, NULL);
#endif /* !OPENSSL_NO_NEXTPROTONEG */
}

static int
ssl_handshake(SSL *ssl, int fd) 
{
	int rv;
	if (SSL_set_fd(ssl, fd) == 0) {
		error("ssl: %s ", ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}
	ERR_clear_error();
	rv = SSL_connect(ssl);
	if (rv <= 0) {
		error("ssl: %s", ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}
	return 0;
}

static int 
connect_to(const char *host, u16 port) 
{
	struct addrinfo hints;
	int fd = -1;
	int rv;
	char service[NI_MAXSERV];
	struct addrinfo *res, *rp;

	snprintf(service, sizeof(service), "%u", port);
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	rv = getaddrinfo(host, service, &hints, &res);
	if (rv != 0) {
		error("getaddrinfo: %s", gai_strerror(rv));
		return -1;
	}

	for (rp = res; rp; rp = rp->ai_next) {
		fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (fd == -1)
			continue;

		rv = connect(fd, rp->ai_addr, rp->ai_addrlen);
		if (rv == 0)
			break;
		
		close(fd);
		fd = -1;
	}
	freeaddrinfo(res);
	return fd;
}

static void
make_non_block(int fd)
{
	int flags, rv;
	while ((flags = fcntl(fd, F_GETFL, 0)) == -1 && errno == EINTR);
	if (flags == -1) {
		error("fcntl: %s", strerror(errno));
	}

	while ((rv = fcntl(fd, F_SETFL, flags | O_NONBLOCK)) == -1 && errno == EINTR);
	if (rv == -1) {
		error("fcntl: %s", strerror(errno));
	}
}

static void
set_tcp_nodelay(int fd) 
{
	int val = 1;
	int rv;
	rv = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, (socklen_t)sizeof(val));
	if (rv == -1) {
		error("setsockopt: %s", strerror(errno));
	}
}

static void 
ctl_poll(struct pollfd *pollfd, struct connection *conn) 
{
	pollfd->events = 0;
	if (nghttp2_session_want_read(conn->sess) || conn->wio == WANT_READ) 
			pollfd->events |= POLLIN;
	if (nghttp2_session_want_write(conn->sess) || conn->wio == WANT_WRITE)
			pollfd->events |= POLLOUT;
}

static void 
submit_request(struct connection *connection, struct request *req) 
{
	s32 stream_id;

	const nghttp2_nv nva[] = {MAKE_NV(":method", "GET"),
	MAKE_NV_CS(":path", req->path),
	MAKE_NV(":scheme", "https"),
	MAKE_NV_CS(":authority", req->hostport),
	MAKE_NV("accept", "*/*"),
	MAKE_NV("user-agent", "machine/" NGHTTP2_VERSION)};

	stream_id = nghttp2_submit_request(connection->sess, NULL, nva,
	                              sizeof(nva) / sizeof(nva[0]), NULL, req);

	if (stream_id < 0) {
		error("nghttp2_submit_request sid=%d", stream_id);
	}

	req->stream_id = stream_id;
	info("stream_id: %d", stream_id);
}

static void 
exec_io(struct connection *connection) 
{
	int rv = nghttp2_session_recv(connection->sess);
	if (rv != 0) {
		error("nghttp2_session_recv");
	}
	rv = nghttp2_session_send(connection->sess);
	if (rv != 0) {
		error("nghttp2_session_send");
	}
}

static void 
request_init(struct request *req, const struct uri *uri) 
{
	req->host = strcopy(uri->host, uri->hostlen);
	req->port = uri->port;
	req->path = strcopy(uri->path, uri->pathlen);
	req->hostport = strcopy(uri->hostport, uri->hostportlen);
	req->stream_id = -1;
}

static void 
request_free(struct request *req) 
{
	free(req->host);
	free(req->path);
	free(req->hostport);
}

static void 
fetch_uri(const struct uri *uri) 
{
	nghttp2_session_callbacks *cb;
	int fd;
	SSL_CTX *ssl_ctx;
	SSL *ssl;
	struct request req;
	struct connection connection;
	int rv;
	nfds_t npollfds = 1;
	struct pollfd pollfds[1];

	request_init(&req, uri);

	/* Establish connection and setup SSL */
	fd = connect_to(req.host, req.port);
	if (fd == -1) {
		error("Could not open file descriptor");
	}
	ssl_ctx = SSL_CTX_new(SSLv23_client_method());
	if (ssl_ctx == NULL) {
		error("ssl: %s", ERR_error_string(ERR_get_error(), NULL));
	}
	init_ssl_ctx(ssl_ctx);
	__ssl_init_ctxt(ssl_ctx);

	ssl = SSL_new(ssl_ctx);
	__ssl_callbacks(ssl);

	if (ssl == NULL) {
		error("ssl: %s", ERR_error_string(ERR_get_error(), NULL));
	}
	ssl_handshake(ssl, fd);

	connection.ssl = ssl;
	connection.wio = IO_NONE;

	make_non_block(fd);
	set_tcp_nodelay(fd);

	info("SSL/TLS handshake completed");
	rv = nghttp2_session_callbacks_new(&cb);
	if (rv != 0) {
		error("nghttp2_session_callbacks_new");
	}

	setup_nghttp2_callbacks(cb);
	rv = nghttp2_session_client_new(&connection.sess, cb, &connection);
	nghttp2_session_callbacks_del(cb);
	if (rv != 0) {
		error("nghttp2_session_client_new");
	}

	rv = nghttp2_submit_settings(connection.sess,NGHTTP2_FLAG_NONE,NULL,0);
	if (rv != 0)
		error("nghttp2_submit_settings");

	submit_request(&connection, &req);

	pollfds[0].fd = fd;
	ctl_poll(pollfds, &connection);

	while (nghttp2_session_want_read(connection.sess) ||
		nghttp2_session_want_write(connection.sess)) {
		int nfds = poll(pollfds, npollfds, -1);
		if (nfds == -1) {
			error("poll: %s", strerror(errno));
		}
		if (pollfds[0].revents & (POLLIN | POLLOUT)) {
			exec_io(&connection);
		}
		if ((pollfds[0].revents & POLLHUP) || (pollfds[0].revents & POLLERR)) {
			error("Connection error");
		}
		ctl_poll(pollfds, &connection);
	}
	
	nghttp2_session_del(connection.sess);
	SSL_shutdown(ssl);
	SSL_free(ssl);
	SSL_CTX_free(ssl_ctx);
	shutdown(fd, SHUT_WR);
	close(fd);
	request_free(&req);
}

static int 
parse_uri(struct uri *res, const char *uri) 
{

	size_t len, i, offset;
	int ipv6addr = 0;
	memset(res, 0, sizeof(struct uri));
	len = strlen(uri);
	if (len < 9 || memcmp("https://", uri, 8) != 0)
		return -1;
	
	offset = 8;
	res->host = res->hostport = &uri[offset];
	res->hostlen = 0;
	if (uri[offset] == '[') {
		++offset;
		++res->host;
		ipv6addr = 1;
		for (i = offset; i < len; ++i) {
			if (uri[i] == ']') {
				res->hostlen = i - offset;
				offset = i + 1;
				break;
			}
		}
	} else {
		const char delims[] = ":/?#";
		for (i = offset; i < len; ++i) {
		if (strchr(delims, uri[i]) != NULL) {
			break;
		}
	}
	res->hostlen = i - offset;
	offset = i;
	}
	if (res->hostlen == 0) {
		return -1;
	}

	res->port = 443;
	if (offset < len) {
		if (uri[offset] == ':') {

			const char delims[] = "/?#";
			int port = 0;
			++offset;
			for (i = offset; i < len; ++i) {
				if (strchr(delims, uri[i]) != NULL) {
					break;
				}
				if ('0' <= uri[i] && uri[i] <= '9') {
					port *= 10;
					port += uri[i] - '0';
					if (port > 65535) {
						return -1;
					}
				} else {
					return -1;
				}
			}
			if (port == 0) {
				return -1;
			}
			offset = i;
			res->port = (uint16_t)port;
		}
	}
	res->hostportlen = (size_t)(uri + offset + ipv6addr - res->host);
	for (i = offset; i < len; ++i) {
		if (uri[i] == '#') {
			break;
		}
	}
	if (i - offset == 0) {
		res->path = "/";
		res->pathlen = 1;
	} else {
		res->path = &uri[offset];
		res->pathlen = i - offset;
	}
	return 0;
}

struct http2 *
http2_new(void)
{
	if (!http2_initialized)
		http2_initialized = 1;

	SSL_library_init();
	OpenSSL_add_ssl_algorithms();
	SSL_load_error_strings();
	ERR_load_crypto_strings();

	setenv("OPENAAA_PROTOCOL", "aaa", 0);

	struct mm_pool *mp = mm_pool_create(CPU_PAGE_SIZE, 0);
	struct http2 *http2 = mm_pool_zalloc(mp, sizeof(*http2));

	http2->mp = mp;
	http2->mp_attrs = mm_pool_create(CPU_PAGE_SIZE, 0);

        log_open("syslog", 0);
	log_verbose = 4;
        
	return http2;
}

void
http2_free(struct http2 *http2)
{
	mm_pool_destroy(http2->mp_attrs);
	mm_pool_destroy(http2->mp);
}

int
http2_connect(struct http2 *http2, const char *url)
{
	mm_pool_flush(http2->mp_attrs);
	debug1("connect(url: %s)", url);
	
	struct uri uri;
	parse_uri(&uri, url); 
	fetch_uri(&uri); 
	return 0;
}

int
http2_submit(struct http2 *http2, int stream_id, const char *uri)
{
	struct uri uri;
	parse_uri(&uri, url); 
	
	return 0;
}

int
http2_disconnect(struct http2 *http2)
{
	return 0;
}

int
http2_read(struct http2 *http2, int stream_id, char *buf, int size)
{
	return 0;
}
	
int
http2_write(struct http2 *http2, int stream_id, char *buf, int size)
{
	return 0;
}
	
int
http2_attr_set(struct http2 *http2, const char *attr, const char *value)
{
	if (!attr || !value)
		return -EINVAL;

	return 0;
}

const char *
http2_attr_get(struct http2 *http2, const char *attr)
{
        info("http2_get");
	if (!attr || !*attr)
		return NULL;

	if (!strcmp(attr, "aaa.sess.id"))
		return aaa_sess_id;
	else if (!strcmp(attr, "aaa.bind.id"))
		return aaa_bind_id;
	else if (!strcmp(attr, "aaa.bind.key"))
		return aaa_bind_key;
	else if (!strcmp(attr, "aaa.authority"))
		return aaa_authority;
	
	return NULL;
}
