/*
 * $id: socache.c                            Daniel Kubec <niel@rtfm.cz> $
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


#include "httpd.h"
#include "http_config.h"
#include "apr.h"
#include "apu_version.h"
#include "ap_socache.h"
#include "ap_mpm.h"
#include "http_log.h"
#include "mod_tls_aaa.h"
#include "private.h"

#ifdef PACKAGE_VERSION
#undef PACKAGE_VERSION
#endif

#include <ctypes/lib.h>
#include <ctypes/utils.h>
#include <ctypes/string.h>
#include <mem/stack.h>

#include <aaa/lib.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

/* Converts a hex character to its integer value */
char 
from_hex(char ch) 
{
	return isdigit(ch) ? ch - '0' : tolower(ch) - 'a' + 10;
}

/* Converts an integer value to its hex character*/
char 
to_hex(char code) 
{
	static char hex[] = "0123456789abcdef";
	return hex[code & 15];
}

static const char *
sc_create(ap_socache_instance_t **ctx, const char *arg, 
          apr_pool_t *tmp, apr_pool_t *p)
{
	return NULL;
}

static void
sc_destroy(ap_socache_instance_t *ctx, server_rec *s)
{
}

static apr_status_t
sc_init(ap_socache_instance_t *ctx,
        const char *ns, const struct ap_socache_hints *hints, 
        server_rec *s, apr_pool_t *p)
{
	ap_module_trace_scall(s);
	struct aaa *aaa = (struct aaa*)ctx;
	return APR_SUCCESS;
}

static apr_status_t
sc_store(ap_socache_instance_t *ctx, server_rec *s, 
         const unsigned char *id, unsigned int len, apr_time_t exp, 
	 unsigned char *d, unsigned int dlen, apr_pool_t *p)
{
	ap_module_trace_scall(s);

	struct srv *srv = ap_get_module_config(s->module_config, &MODULE_ENTRY);
        struct aaa *aaa = srv->aaa;

	char key[(len * 2) + 1];
	mem_to_hex(key, (char *)id, len, 0);
	key[len * 2] = 0;

	s_info(s, "sess.id: %s", key);

        char val[(dlen * 2) + 1];
        mem_to_hex(val, (char *)d, dlen, 0);
	val[dlen * 2] = 0;
	if (aaa_bind(aaa, AAA_BIND_SESSION_ID, key))
		APR_EINVAL;

	aaa_attr_set(aaa, "sess.i2d", val);
	aaa_attr_set(aaa, "sess.expires", stk_printf("%d", 300));

	return APR_SUCCESS;
}

static apr_status_t
sc_retrieve(ap_socache_instance_t *ctx, server_rec *s, 
            const unsigned char *id, unsigned int len, 
	    unsigned char *d, unsigned int *dlen, apr_pool_t *p)
{
	ap_module_trace_scall(s);

	struct srv *srv = ap_get_module_config(s->module_config, &MODULE_ENTRY);
	struct aaa *aaa = srv->aaa;

	char key[(len * 2) + 1];
	mem_to_hex(key, (char *)id, len, 0);
	key[len * 2] = 0;
	s_info(s, "sess.id: %s", key);

	if (aaa_bind(aaa, AAA_BIND_SESSION_ID, key))
		return APR_NOTFOUND;
	if (aaa_select(aaa, NULL))
		return APR_NOTFOUND;

	const char *v = aaa_attr_get(aaa, "sess.i2d");
	if (!v)
		return APR_NOTFOUND;

	unsigned int size = strlen(v);
	if (!size)
		return APR_NOTFOUND ;

	*dlen = size / 2;
	hex_to_mem((byte *)d, (const char *)v, size / 2, 0);

	return APR_SUCCESS;
}

static apr_status_t
sc_remove(ap_socache_instance_t *ctx, server_rec *s, 
          const unsigned char *id, unsigned int len, apr_pool_t *p)
{
	ap_module_trace_scall(s);
	return APR_ENOTIMPL;
}

static void
sc_status(ap_socache_instance_t *ctx, request_rec *r, int flags)
{
	ap_module_trace_rcall(r);
}

static apr_status_t
sc_iterate(ap_socache_instance_t *ctx, server_rec *s, void *user, 
           ap_socache_iterator_t *it, apr_pool_t *p)
{
	ap_module_trace_scall(s);
	return APR_ENOTIMPL;
}

const ap_socache_provider_t socache_tls_aaa = {
	"openaaa",
	0,
	sc_create,
	sc_init,
	sc_destroy,
	sc_store,
	sc_retrieve,
	sc_remove,
	sc_status,
	sc_iterate
};
