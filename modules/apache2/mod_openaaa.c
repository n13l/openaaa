/*
 * $id: mod_tls_aaa.c                               Daniel Kubec <niel@rtfm.cz>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#undef HAVE_STRING_H
#undef PACKAGE_NAME
#undef PACKAGE_VERSION

#include <stdlib.h>
#include <unistd.h>
#include <ap_config.h>
#include <ap_socache.h>
#include <apr_strings.h>
#include <httpd.h>
#include <http_config.h>
#include <http_connection.h>
#include <http_core.h>
#include <http_log.h>
#include <http_main.h>
#include <http_request.h>
#include <http_protocol.h>
#include <util_filter.h>
#include <util_script.h>

#include "httpd.h"
#include "http_config.h"
#include "http_main.h"
#include "http_protocol.h"
#include "http_core.h"

#include "mod_openaaa.h"
#include "private.h"
#include "optional.h"

/* AAA abstraction */
#include <mem/stack.h>
#include <aaa/lib.h>
#include <crypto/sha1.h>
#include <crypto/hex.h>

/* mod_ssl interface */
APR_OPTIONAL_FN_TYPE(ssl_is_https)               *ssl_is_https;
APR_OPTIONAL_FN_TYPE(ssl_var_lookup)             *ssl_var_lookup;
APR_OPTIONAL_FN_TYPE(ssl_export_keying_material) *ssl_keying_material;
APR_OPTIONAL_FN_TYPE(ssl_renegotiation)          *ssl_renegotiation;
APR_OPTIONAL_FN_TYPE(modssl_register_npn)        *modssl_register_npn;

static const char *aaa_id;

/*
 * Gives modules a chance to create their request_config entry when the
 * request is created.
 * @param r The current request
 * @ingroup hooks
 */

static int
create_request(request_rec *r);

static apr_status_t
destroy_request(void *ctx);

static void
custom_log(server_rec *s, unsigned level, const char *msg);

/*
 * Run the child_init functions for each module
 * @param pchild The child pool
 * @param s The list of server_recs in this server
 */

static void
child_init(apr_pool_t *p, server_rec *s)
{
	aps_trace_call(s);

	struct aaa *a = aaa_new(0);
	//aaa_set_opt(a, AAA_OPT_USERDATA, (const char *)s);
	//aaa_set_opt(a, AAA_OPT_CUSTOMLOG, (char *)custom_log);

	for (; s; s = s->next) {
		struct srv *srv;
		srv = ap_get_module_config(s->module_config, &MODULE_ENTRY);
		srv->pid = getpid();
		srv->aaa = a;
		srv->mod_ssl = ap_find_linked_module("mod_ssl.c");
	}

	apr_pool_cleanup_register(p, a, child_fini, child_fini);
}

/*
 * Run the child_fini functions for each module
 * @param ctx The ctxt in this server
 */

static apr_status_t
child_fini(void *ctx)
{
	struct aaa *a = (struct aaa*)ctx;
	aaa_free(a);
	return 0;
}

/*
 * The npn_advertise_protos callback allows another modules to add
 * entries to the list of protocol names advertised by the server
 * during the Next Protocol Negotiation (NPN) portion of the SSL
 * handshake.  The callback is given the connection and an APR array;
 * it should push one or more char*'s pointing to NUL-terminated
 * strings (such as "http/1.1" or "spdy/2") onto the array and return
 * OK.  To prevent further processing of (other modules') callbacks,
 * return DONE. 
 */

int
npn_advertise_protos(conn_rec *c, apr_array_header_t *protos)
{
	void **item = apr_array_push(protos);
	*item = (void *)"tls-aaa";

	return DECLINED;
}

/* 
 * The npn_proto_negotiated callback allows other modules to discover
 * the name of the protocol that was chosen during the Next Protocol
 * Negotiation (NPN) portion of the SSL handshake.  Note that this may
 * be the empty string (in which case modules should probably assume
 * HTTP), or it may be a protocol that was never even advertised by
 * the server.  The callback is given the connection, a
 * non-NUL-terminated string containing the protocol name, and the
 * length of the string; it should do something appropriate
 * (i.e. insert or remove filters) and return OK.  To prevent further
 * processing of (other modules') callbacks, return DONE. 
 */

static int 
npn_proto_negotiated(conn_rec *c, const char *name, apr_size_t len)
{
	return DECLINED;
}

/*
 * Run the post_config function for each module
 * @param pconf The config pool
 * @param plog The logging streams pool
 * @param ptemp The temporary pool
 * @param s The list of server_recs
 * @return OK or DECLINED on success anything else is a error
 */

static int
post_config(apr_pool_t *p, apr_pool_t *l, apr_pool_t *t, server_rec *s)
{
	struct srv *srv = ap_get_module_config(s->module_config, &MODULE_ENTRY);
	ap_add_version_component(p, APACHE2_TLS_AAA_MODULE_VERSION);
	return OK;
}

static void
optional_fn_retrieve(void)
{
	ssl_is_https        = APR_RETRIEVE_OPTIONAL_FN(ssl_is_https);
	ssl_var_lookup      = APR_RETRIEVE_OPTIONAL_FN(ssl_var_lookup);
	ssl_keying_material = APR_RETRIEVE_OPTIONAL_FN(ssl_export_keying_material);
/*	
	ssl_renegotiation   = APR_RETRIEVE_OPTIONAL_FN(ssl_renegotiation);
	modssl_register_npn = APR_RETRIEVE_OPTIONAL_FN(modssl_register_npn);
*/	
}

/*
 * Gives modules a chance to create their request_config entry when the
 * request is created.
 * @param r The current request
 * @ingroup hooks
 */

static int
create_request(request_rec *r)
{
	struct srv *srv = ap_srv_config_get(r);
	struct req *req = apr_pcalloc(r->pool, sizeof(*req));
	req->r = r;
	ap_req_config_set(r, req);
	apr_pool_cleanup_register(r->pool, r,destroy_request,destroy_request);

	return DECLINED;
}

static apr_status_t
destroy_request(void *ctx)
{
	request_rec *r = ctx;
	return DECLINED;
}

static inline void
fixups_publickey(char *str, unsigned int len)
{
	char *p = str;
	for (unsigned int i = 0; i < len && *p; i++, p++)
		if (*p == '\r' || *p == ' ' || *p == '\t')
			continue;
		else
			*str++ = *p;
	*str = 0;
}

static const char *
export_public_key(request_rec *r)
{
	char *cert = ssl_var_lookup(ssl_lookup_args, "SSL_SERVER_CERT");
	char *pub = ap_x509_pubkey_from_cert(r->pool, cert, strlen(cert));

	if (!pub)
		return NULL;

	apr_table_t *t = r->subprocess_env;
	apr_table_add(t, "SERVER_PUBLIC_KEY", pub);

	fixups_publickey(pub, strlen(pub));

	return pub;
}

static const char *
export_keying_material(request_rec *r)
{
	if (!ssl_keying_material)
		return NULL;

	struct srv *srv = ap_srv_config_get(r);

	unsigned char *sec = alloca(srv->keymat_len + 1);
	unsigned int len = srv->keymat_len;

	const char *lab = srv->keymat_label;
	lab = "EXPORTER_AAA";
	unsigned int lsize = strlen(lab);

	ssl_keying_material(r->connection, sec, len, lab, lsize, NULL, 0, 0);

        char *k = apr_pcalloc(r->pool, (len * 2) + 1);
        //memhex(k, (const char *)sec, len);
	k[len * 2] = 0;
	return k;
}

static const char *
export_keying_derivate(request_rec *r, const char *pub, const char *key)
{
	return NULL;
	return ap_keying_material_pubkey_derivate(r->pool, key, pub);
}

static int
tls_authentication_signal(request_rec *r)
{
	struct srv *srv = ap_srv_config_get(r);
	if (!srv->keymat_label || !srv->keymat_len)
		return 0;

	const char *v = ssl_var_lookup(ssl_lookup_args, "SSL_SESSION_RESUMED");
	return !strcasecmp(v, "Initial");
}

static int
iterate_func(void *req, const char *key, const char *value) 
{
	int stat;
	char *line;
	request_rec *r = (request_rec *)req;
	if (key == NULL || value == NULL || value[0] == '\0')
		return 1;

	r_info(r, "%s => %s\n", key, value);
			    
	return 1;
}

static inline void
str_collapse(char *str)
{
	char *a = str, *b = str;
	do while (*b == ' ') b++;
		while ((*a++ = *b++));
}

static inline void
rm_newline_char(const char *str)
{
	for(char *p = (char *)str; *p; p++)
		if (*p == '\n' || *p == '\r')
			*p = ' ';
}

static void
parse_session(request_rec *r, const char *file)
{
        struct req *req = ap_req_config_get(r);
        struct srv *srv = ap_srv_config_get(r);
        struct aaa *aaa = srv->aaa;

	char n[4096] = {0}, v[4096] = {0};

	FILE *f = fopen(file, "r");
	if (f == NULL || feof(f))
		return;

	do {
		*n = 0;
		*v = 0;
		fscanf(f, "%s %s", n, v);
		rm_newline_char(n);
		rm_newline_char(v);
		str_collapse(n);
		str_collapse(v);
		if (!*n || !*v)
			break;

		if (!strcasecmp(n, "cn"))
			aaa_attr_set(srv->aaa, "user.name", (char *)v);

		if (!strcasecmp(n, "mail")) {
			aaa_attr_set(srv->aaa, "user.id", (char *)v);
			aaa_attr_set(srv->aaa, "user.mail", (char *)v);
		}

		if (!strcasecmp(n, "mobile"))
			aaa_attr_set(srv->aaa, "user.mobile", (char *)v);

		r_info(r, "%s=%s\n", n, v);
	} while(!feof(f));

	aaa_commit(srv->aaa);
	fclose(f);
}

static int
external_aaa(request_rec *r)
{
        struct srv *srv = ap_srv_config_get(r);
        struct aaa *aaa = srv->aaa;

        const char *sid = aaa_attr_get(aaa, "sess.key");
        const char *key = sid;

	/*
	const char *authority = "orange.alucid.eu";

        byte *enkey = alloca(512);
        memset(enkey, 0, 511);
        base64_encode(enkey, (byte *)key, strlen(key));

        sha1_context sha1;
        sha1_init(&sha1);
        sha1_update(&sha1, (byte *)key, strlen(key));
        char *id = stk_mem_to_hex((char *)sha1_final(&sha1), SHA1_SIZE / 2);

	aaa_attr_set(aaa,"sess.sec", id);
	aaa_commit(aaa);

        byte *enid = alloca(512);
        memset(enid, 0, 511);
        base64_encode(enid, (byte *)id, strlen(id));

        char *bind_id = "MQ%3D%3D";
        char *uri_id  = url_encode(enid);
        char *uri_key = url_encode(enkey);

        char *r3 = stk_printf("http%%3A%%2F%%2F%s%%2FAIM%%2Fservices%%2FR3", authority);

        char *uri_win32 = stk_printf("alucid://callback?authId=%s^&r3Url=%s^&bindingId=%s^&bindingKey=%s",
	                             uri_id, r3, bind_id, uri_key);

	char *uri_unix = stk_printf("alucid://callback?authId=%s\\&r3Url=%s\\&bindingId=%s\\&bindingKey=%s",
	                             uri_id, r3, bind_id, uri_key);

        pid_t fk = fork();
        if (!fk) {

		r_info(r, "external authentication uri: %s", uri_unix);
		int status = system(stk_printf("%s %s", 
					"/usr/local/bin/aducidr3", uri_unix));
                int rv = WEXITSTATUS(status);
		r_info(r, "auth status=%d", rv);
		if (status != 0)
			_exit(127);

		const char *file = stk_printf("/tmp/aaa-%s", id);
		r_info(r, "authentized session file=%s", file);
		parse_session(r, file);
		_exit(127);
	}

        free(uri_id);
        free(uri_key);
*/	
	return DECLINED;
}

static int
http_authentication_signal(request_rec *r)
{
	//apr_table_do(iterate_func, r, r->headers_in, NULL);
/*
	if (!apr_table_get(r->headers_in, "AAA-NEGOTIATE"))
		return 0;
*/
	if (r->method_number != M_POST)
		return DECLINED;

	r_info(r, "http authentication signal: AAA_NEGOTIATE");

	return external_aaa(r);
}

/*
 * This hook gives protocol modules an opportunity to set everything up
 * before calling the protocol handler.  All pre-connection hooks are
 * run until one returns something other than ok or decline
 * @param c The connection on which the request has been received.
 * @param csd The mechanism on which this connection is to be read.
 *            Most times this will be a socket, but it is up to the module
 *            that accepts the request to determine the exact type.
 * @return OK or DECLINED
 */

static int
pre_connection(conn_rec *c, void *csd)
{
	//modssl_register_npn(c, npn_advertise_protos, npn_proto_negotiated);
	return DECLINED;
}

/*
 * This hook allows modules to affect the request immediately after the request
 * has been read, and before any other phases have been processes.  This allows
 * modules to make decisions based upon the input header fields
 * @param r The current request
 * @return OK or DECLINED
 */

static int
post_read_request(request_rec *r)
{
	if (!ap_is_initial_req(r))
		return DECLINED;

	ap_module_trace_rcall(r);
/*
	if ( !ssl_keying_material)
		return DECLINED;
*/
	if (!ssl_is_https)
		return DECLINED;
	if (!ssl_var_lookup || !ssl_is_https(r->connection))
		return DECLINED;

	struct req *req = ap_req_config_get(r);
	struct srv *srv = ap_srv_config_get(r);
	struct aaa *aaa = srv->aaa;

	r_info(r, "uri: %s", r->uri);

	const char *pub = export_public_key(r);
	const char *key = aaa_attr_get(aaa, "sess.key");
	const char *sec = aaa_attr_get(aaa, "sess.sec");
	const char *id = aaa_attr_get(aaa, "sess.id");

	r_info(r, "sess.id: %s", id);

	if (key)
		r_info(r, "sess.key: %s", key);
	if (sec)
		r_info(r, "sess.sec: %s", sec);

	apr_table_t *t = r->subprocess_env;
        apr_table_setn(t, "AAA_SESS_KEY",  aaa_attr_get(aaa, "sess.key"));
        apr_table_setn(t, "AAA_SESS_SEC",  aaa_attr_get(aaa, "sess.sec"));

	if (sec) {
		const char *file = printfa("/tmp/aaa-%s", sec);
		r_info(r, "authentized session file=%s", file);
		parse_session(r, file);
	}


	if (!tls_authentication_signal(r))
		return DECLINED;

	key = export_keying_material(r);
	sec = export_keying_derivate(r, pub, key);

        if (key)
		r_info(r, "sess.key: %s", key);
	if (sec)
		r_info(r, "sess.sec: %s", sec);

	apr_table_setn(t, "AAA_SESS_KEY",  aaa_attr_get(aaa, "sess.key"));
	apr_table_setn(t, "AAA_SESS_SEC",  aaa_attr_get(aaa, "sess.sec"));	

	aaa_attr_set(srv->aaa, "sess.key", (char *)key);
	aaa_attr_set(srv->aaa, "sess.sec", (char *)sec);
	aaa_commit(srv->aaa);

	return DECLINED;
}

/**
 * Register a hook function that will analyze the request headers,
 * authenticate the user, and set the user information in the request record.
 * @param pf A check_user_id hook function
 * @param aszPre A NULL-terminated array of strings that name modules whose
 *               hooks should precede this one
 * @param aszSucc A NULL-terminated array of strings that name modules whose
 *                hooks should succeed this one
 * @param nOrder An integer determining order before honouring aszPre and
 *               aszSucc (for example, HOOK_MIDDLE)
 * @param type Internal request processing mode, either
 *             AP_AUTH_INTERNAL_PER_URI or AP_AUTH_INTERNAL_PER_CONF
 */

static int
check_authn(request_rec *r)
{
	ap_module_trace_rcall(r);

	/*
	* We decline when we are in a subrequest.  The Authorization header
	* would already be present if it was added in the main request.
	*/

	if (!ap_is_initial_req(r))
		return DECLINED;

	r_info(r, "auth.type: %s", ap_auth_type(r));

	struct req *req = ap_req_config_get(r);
	if (!req->user.name)
		return DECLINED;

	r->user = apr_pstrdup(r->pool, req->user.name);

	return DECLINED;
}

/*
 * This hook is used to apply additional access control to this resource.
 * It runs *before* a user is authenticated, so this hook is really to
 * apply additional restrictions independent of a user. It also runs
 * independent of 'Require' directive usage.
 *
 * @param r the current request
 * @return OK, DECLINED, or HTTP_...
 * @ingroup hooks
 */

static int
access_checker(request_rec *r)
{
	/*
	 * We decline when we are in a subrequest.  The Authorization header
	 * would already be present if it was added in the main request.
	 */

	if (!ap_is_initial_req(r))
		return DECLINED;

	ap_module_trace_rcall(r);
	//r_info(r, "uri: %s", r->uri);

	/* checking for tls authentification for this reqeust */
	if (!ap_auth_type(r) || strcasecmp(ap_auth_type(r), "TLS-AAA"))
		return DECLINED;

	struct req *req = ap_req_config_get(r);
	struct srv *srv = ap_srv_config_get(r);
	struct aaa *aaa = srv->aaa;
	struct user *user = &req->user;

	user->name = aaa_attr_get(aaa, "user.name");
	user->uuid = aaa_attr_get(aaa, "user.uuid");

	http_authentication_signal(r);

	/*
	* We return HTTP_UNAUTHORIZED (401) because the client may wish
	* to authenticate using a different scheme, or a different
	* user. If this works, they can be granted access. If we
	* returned HTTP_FORBIDDEN (403) then they don't get a second
	* chance.
	*/

	if (r->method_number == M_POST) {
		apr_table_setn(r->err_headers_out, "X-AAA-ID", 
		               "http://aaa.rtfm.cz/auth");
		apr_table_setn(r->err_headers_out, "X-AAA-HANDLER", "qrcode");

		r_info(r, "AAA-NEGOTIATE");
		//return HTTP_UNAUTHORIZED;
	}

	if (user->name)
		apr_table_add(r->subprocess_env, "REMOTE_USER", user->name);

	const char *sec = aaa_attr_get(aaa, "sess.sec");

	//r_info(r, "sess.id: %s", aaa_attr_get(aaa, "sess.id"));
	if (sec)
		r_info(r, "sess.sec: %s", sec);
	//r_info(r, "user.uuid: %s", user->uuid);
	if (user->name)
		r_info(r, "user.name: %s", user->name);

	return DECLINED;
}

/*
 * Register a hook function that will apply additional access control to
 * the current request.
 * @param pf An access_checker hook function
 * @param aszPre A NULL-terminated array of strings that name modules whose
 *               hooks should precede this one
 * @param aszSucc A NULL-terminated array of strings that name modules whose
 *                hooks should succeed this one
 * @param nOrder An integer determining order before honouring aszPre and
 *               aszSucc (for example, HOOK_MIDDLE)
 * @param type Internal request processing mode, either
 *             AP_AUTH_INTERNAL_PER_URI or AP_AUTH_INTERNAL_PER_CONF
 */

static int
check_access(request_rec *r)
{
	ap_module_trace_rcall(r);
	return DECLINED;
}

/*
 * This hook is used to check to see if the resource being requested
 * is available for the authenticated user (r->user and r->ap_auth_type).
 * It runs after the access_checker and check_user_id hooks. Note that
 * it will *only* be called if Apache determines that access control has
 * been applied to this resource (through a 'Require' directive).
 *
 * @param r the current request
 * @return OK, DECLINED, or HTTP_...
 * @ingroup hooks
 */

static int
auth_checker(request_rec *r)
{
	ap_module_trace_rcall(r);
	return DECLINED;
}

/*
 * At this step all modules can have a last chance to modify the 
 * response header (for example set a cookie) before the calling 
 * the content handler.
 *
 * @param r The current request
 * @return OK, DECLINED, or HTTP_...
 * @ingroup hooks
 */

static int
fixups(request_rec *r)
{
	ap_module_trace_rcall(r);
	//r_info(r, "uri: %s", r->uri);

	struct srv *srv = ap_srv_config_get(r);
	struct aaa *a = srv->aaa;

	apr_table_t *t = r->subprocess_env;
        apr_table_setn(t, "AAA_SESS_ID",  aaa_attr_get(a, "sess.id"));
        apr_table_setn(t, "AAA_SESS_CREATED", aaa_attr_get(a, "sess.created"));
	apr_table_setn(t, "AAA_SESS_MODIFIED",aaa_attr_get(a, "sess.modified"));
	apr_table_setn(t, "AAA_SESS_ACCESS", aaa_attr_get(a, "sess.access"));
	apr_table_setn(t, "AAA_SESS_EXPIRES", aaa_attr_get(a, "sess.expires"));
        apr_table_setn(t, "AAA_SESS_KEY",  aaa_attr_get(a, "sess.key"));
        apr_table_setn(t, "AAA_SESS_SEC",  aaa_attr_get(a, "sess.sec"));	
	apr_table_setn(t, "AAA_USER_ID",   aaa_attr_get(a, "user.id"));
	apr_table_setn(t, "AAA_USER_NAME", aaa_attr_get(a, "user.name"));

	const char *user = aaa_attr_get(a, "user.name");
	if (user)
		r_info(r, "user.name: %s", user);

	return DECLINED;
}

static void *
config_init_srv(apr_pool_t *p, server_rec *s)
{
	struct srv *srv = apr_pcalloc(p, sizeof(*srv));
	return srv;
}

static void *
config_init_dir(apr_pool_t *p, char *d)
{
	struct dir *dir = apr_pcalloc(p, sizeof(*dir));
	return dir;
}

static const char *
config_tls(cmd_parms *cmd, void *d, const char *v)
{
	struct srv *s = ap_srv_config_get_cmd(cmd);

	const char *arg;
	const char *word = ap_getword_conf(cmd->pool, &arg);
	if (!strncasecmp(word, "plus", 1)) {
		word = ap_getword_conf(cmd->pool, &arg);
	};

	return ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE);
}

static const char *
config_aaa_id(cmd_parms *cmd, void *d, const char *v)
{
	struct srv *s = ap_srv_config_get_cmd(cmd);
	aaa_id = apr_pstrdup(cmd->pool, v);

	return ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE);
}

/*
 * Labels here have the same definition as in TLS, i.e., an ASCII string
 * with no terminating NULL.  Label values beginning with "EXPERIMENTAL"
 * MAY be used for private use without registration.  All other label
 * values MUST be registered via Specification Required as described by
 * RFC 5226 [RFC5226].  Note that exporter labels have the potential to
 * collide with existing PRF labels.  In order to prevent this, labels
 * SHOULD begin with "EXPORTER".  This is not a MUST because there are
 * existing uses that have labels which do not begin with this prefix.
 */

static const char *
config_aaa_label(cmd_parms *cmd, void *d, const char *v)
{
	struct srv *s = ap_srv_config_get_cmd(cmd);
	s->keymat_label = v;
	return ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE);
}

/*
 * Keying Material Exporter bytes (default 20)
 */

static const char *
config_aaa_len(cmd_parms *cmd, void *d, const char *v)
{
	struct srv *s = ap_srv_config_get_cmd(cmd);
	s->keymat_len = atoi(v);
	return ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE);
}

/*
 * The command record structure.  Each modules can define a table of these
 * to define the directives it will implement.
 */

static const command_rec cmds[] = {
	AP_INIT_TAKE1("TLS", config_tls, NULL, RSRC_CONF,
	              "Configures multiple TLS options"),
	AP_INIT_TAKE1("TLS-AAA-ID", config_aaa_id, NULL, RSRC_CONF, 
	              "Identifies secure side channel"),
	AP_INIT_TAKE1("TLSKeyingMaterialLabel", config_aaa_label, NULL, RSRC_CONF,
	              "Labels here have the same definition as in TLS"),
	AP_INIT_TAKE1("TLSKeyingMaterialLength", config_aaa_len, NULL, RSRC_CONF,
	              "Export len bytes of keying material (default 20)"),	
	{NULL},
};

static void
register_hooks(apr_pool_t *p)
{
	/* pre_connection hook needs to run after mod_ssl connection hook. */
	static const char *pre_ssl[] = { "mod_ssl.c", NULL };

	ap_hook_child_init(child_init, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_optional_fn_retrieve(optional_fn_retrieve, NULL,NULL,APR_HOOK_MIDDLE);
	ap_hook_post_config(post_config, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_pre_connection(pre_connection, pre_ssl, NULL, APR_HOOK_MIDDLE);
	ap_hook_create_request(create_request, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_post_read_request(post_read_request,NULL,NULL, APR_HOOK_LAST);
	ap_hook_check_authn(check_authn, NULL,NULL, APR_HOOK_FIRST, AP_AUTH_INTERNAL_PER_CONF);
	ap_hook_access_checker(access_checker, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_check_access(check_access, NULL, NULL, APR_HOOK_MIDDLE, AP_AUTH_INTERNAL_PER_CONF);
	ap_hook_auth_checker(auth_checker, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_fixups(fixups, NULL, NULL, APR_HOOK_LAST);

	ap_register_provider(p, AP_SOCACHE_PROVIDER_GROUP, "tls-aaa",
	                     AP_SOCACHE_PROVIDER_VERSION, &socache_tls_aaa);
};

static void
custom_log(server_rec *s, unsigned level, const char *msg)
{
}

module AP_MODULE_DECLARE_DATA __attribute__((visibility("default"))) 
MODULE_ENTRY = {
	STANDARD20_MODULE_STUFF,
	config_init_dir,         /* dir config constructor */
	NULL,                    /* dir merger - default is to override */
	config_init_srv,         /* server config constructor */         
	NULL,                    /* merge server config */
	cmds,                    /* command table */            
	register_hooks,          /* Apache2 register hooks */           
};

