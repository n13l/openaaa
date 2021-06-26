/*
 * $Id: mod_auth_TLS.h Daniel Kubec <niel@rtfm.cz> $
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

#ifndef __MOD_AUTH_PRIVATE_H__
#define __MOD_AUTH_PRIVATE_H__

#define MODULE_TRACE_TYPE (APLOG_NOERRNO | APLOG_INFO)

#define ap_debug(s, fmt, ...) \
	ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, fmt, ##__VA_ARGS__)

#define s_info(s, fmt...) \
	ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_INFO, 0, s, fmt)

#define r_debug(r, mask...) \
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0, r, mask)

#define r_notice(r, mask...) \
        ap_log_rerror(APLOG_MARK, APLOG_NOTICE | APLOG_NOERRNO, 0, r, mask)

#define r_error(r, mask...) \
        ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r, mask)

#define r_info(r, mask...) \
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO | APLOG_INFO, 0, r, mask)

#define c_info(c, mask...) \
	ap_log_cerror(APLOG_MARK, APLOG_NOERRNO | APLOG_INFO, 0, c, mask)

#define c_debug(c, mask...) \
	ap_log_cerror(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0, c, mask)

#define ap_module_trace_scall(s) \
	ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "%s:%s()", MODULE_PREFIX, __func__)

#define ap_module_trace_rcall(r) \
	ap_log_rerror(APLOG_MARK, MODULE_TRACE_TYPE, 0, r, "%s:%s()", MODULE_PREFIX, __func__)

#define aps_trace_call(s) \
	ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "%s()", __func__);

#define apr_trace_call(r) \
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0, r, "%s()", __func__);

#define ap_proc_config_get(s) \
        ap_get_module_config(s->pconf, & MODULE_ENTRY)

#define ap_proc_config_set(s, obj) \
        ap_set_module_config(s->pconf, & MODULE_ENTRY, obj)

#define ap_srv_config_get(s) \
        ap_get_module_config(s->module_config, & MODULE_ENTRY)

<<<<<<< HEAD
=======

>>>>>>> 6685c60d0378a981cabbc1ecf552ab3b72be7ac9
#define ap_get_dir_config(r) \
        ap_get_module_config(r->per_dir_config, & MODULE_ENTRY)

#define ap_req_config_get(r) \
        ap_get_module_config(r->request_config, & MODULE_ENTRY)

#define ap_set_srv_config(s, obj) \
        ap_set_module_config(s->module_config, & MODULE_ENTRY, obj)

#define ap_req_config_set(r, obj) \
        ap_set_module_config(r->request_config, & MODULE_ENTRY, obj)

#define ap_srv_config_get_cmd(cmd) \
        ap_get_module_config(cmd->server->module_config, & MODULE_ENTRY)

#define ap_conn_config_get(c) \
        ap_get_module_config((c)->conn_config, & MODULE_ENTRY)

#define ap_conn_config_set(c, obj) \
        ap_set_module_config((c)->conn_config, & MODULE_ENTRY, obj)

#define ssl_lookup_args \
    r->pool, r->server, r->connection, r

#define ap_bst(val) val ? "yes": "no"

struct srv {
	void *ctx;
	struct aaa *aaa;
	int tls_aaa_capability;
	int pid;
	const char *aaa_id;
	const char *keymat_label;
	unsigned int keymat_len;
	void *ssl;
	module *mod_ssl;
	module *mod_mpm;
	module *mod_mpm_prefork;
	module *mod_event;
	apr_thread_mutex_t *mutex;

};

struct proc {
	apr_thread_mutex_t *mutex;
};

struct user {
    const char *id;
    const char *uuid;
    const char *name;
};

struct req {
    request_rec *r;
    apr_table_t* attrs;
    struct user user;
    char *uri;
    char *sid;
    char *res;
    char *key;
    char *sec;
};

struct conn {
	void *ssl;
	char tls_id[128];
	int has_id;
};

struct dir {
	const char *name;
	unsigned int enabled;
	unsigned int pedantic;
};

/*
 * Run the child_fini functions for each module
 * @param ctx The auth_tls_ctxt in this server
 */

static apr_status_t
child_fini(void *ctx);

char *
ap_x509_pubkey_from_cert(apr_pool_t *p, const char *b, unsigned int size);

char *
ap_keying_material_pubkey_derivate(apr_pool_t *p, const char *key, const char *pub);

/*
 * Gives modules a chance to create their request_config entry when the
 * request is created.
 * @param r The current request
 * @ingroup hooks
 */

/*
int
create_request(request_rec *r);
apr_status_t
destroy_request(void *ctx);
*/

extern const ap_socache_provider_t socache_tls_aaa;

#endif/*__MOD_AUTH_PRIVATE_H__*/
