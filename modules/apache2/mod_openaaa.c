/*
 * $id: mod_openaaa.c                               Daniel Kubec <niel@rtfm.cz>
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

#include "mod_ssl.h"
#include "mod_ssl_openssl.h"

#include "mod_openaaa.h"
#include "private.h"

/* AAA abstraction */
#include <mem/stack.h>
#include <aaa/lib.h>
#include <crypto/sha1.h>
#include <crypto/hex.h>
#include <crypto/abi/ssl.h>

APLOG_USE_MODULE(aaa);

APR_OPTIONAL_FN_TYPE(ssl_is_https)         *ssl_is_https;
APR_OPTIONAL_FN_TYPE(ssl_var_lookup)       *ssl_var_lookup;

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

/*
static void
custom_log(server_rec *s, unsigned level, const char *msg);
*/
static void
log_write(struct log_ctx *ctx, const char *msg, int len)
{
	server_rec *s = (server_rec *)ctx->user;
	ap_log_error(ctx->file, ctx->line, APLOG_MODULE_INDEX, APLOG_INFO, 0, s, msg);
}

/*
 * Run the child_init functions for each module
 * @param pchild The child pool
 * @param s The list of server_recs in this server
 */

static void
child_init(apr_pool_t *p, server_rec *s)
{
	log_custom_set(log_write, s);

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
	ap_add_version_component(p, MODULE_VERSION);
	return OK;
}

static void
optional_fn_retrieve(void)
{
	ssl_is_https        = APR_RETRIEVE_OPTIONAL_FN(ssl_is_https);
	ssl_var_lookup      = APR_RETRIEVE_OPTIONAL_FN(ssl_var_lookup);
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
	return DECLINED;

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
	return DECLINED;

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

	return DECLINED;

	if (!ap_is_initial_req(r))
		return DECLINED;

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
	return DECLINED;

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
	AP_INIT_TAKE1("TLSKeyingMaterialLabel", config_aaa_label, NULL, RSRC_CONF,
	              "Labels here have the same definition as in TLS"),
	AP_INIT_TAKE1("TLSKeyingMaterialLength", config_aaa_len, NULL, RSRC_CONF,
	              "Export len bytes of keying material (default 20)"),	
	{NULL},
};
/**
 * init_server hook -- allow SSL_CTX-specific initialization to be performed by
 * a module for each SSL-enabled server (one at a time)
 * @param s SSL-enabled [virtual] server
 * @param p pconf pool
 * @param is_proxy 1 if this server supports backend connections
 * over SSL/TLS, 0 if it supports client connections over SSL/TLS
 * @param ctx OpenSSL SSL Context for the server
 */
	
static int
init_server(server_rec *s, apr_pool_t *p, int is_proxy, SSL_CTX *ctx)
{
	ssl_init();
	ssl_init_ctxt(ctx);	
	return 0;
}

/**
 * pre_handshake hook
 * @param c conn_rec for new connection from client or to backend server
 * @param ssl OpenSSL SSL Connection for the client or backend server
 * @param is_proxy 1 if this handshake is for a backend connection, 0 otherwise
 */

static int
pre_handshake(conn_rec *c, SSL *ssl, int is_proxy)
{
	ssl_init_conn(ssl);
	ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, "stream(%ld-%d): ", 0,0);
	return 0;
}

/**
 * proxy_post_handshake hook -- allow module to abort after successful
 * handshake with backend server and subsequent peer checks
 * @param c conn_rec for connection to backend server
 * @param ssl OpenSSL SSL Connection for the client or backend server
 */

static int
proxy_post_handshake(conn_rec *c, SSL *ssl)
{
	return 0;
}

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

	APR_OPTIONAL_HOOK(ssl, init_server, init_server, NULL, NULL, APR_HOOK_MIDDLE);
	APR_OPTIONAL_HOOK(ssl, pre_handshake, pre_handshake, NULL, NULL, APR_HOOK_MIDDLE);
	APR_OPTIONAL_HOOK(ssl, proxy_post_handshake, proxy_post_handshake, NULL, NULL, APR_HOOK_MIDDLE);

	ap_register_provider(p, AP_SOCACHE_PROVIDER_GROUP, "openaaa",
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
