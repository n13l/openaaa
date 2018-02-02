#define _GNU_SOURCE 1
//#define ENABLE_SSL

#include <sys/compiler.h>
#include <sys/cpu.h>
#include <sys/dll.h>
#include <mem/pool.h>
#include <sys/log.h>

#include <aaa/lib.h>
#include <aaa/prv.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <crypto/abi/lib.h>
#include <modules/openvpn/plugin.h>

#define OVPN_MASK OPENVPN_PLUGIN_MASK
#define OVPN_ENV_EKM "exported_keying_material"

#undef KBUILD_MODNAME
#define KBUILD_MODNAME "vpn"

enum ovpn_endpoint { VPN_CLIENT, VPN_SERVER };

struct ovpn_ctxt {
	struct mm_pool *mp;
	struct mm_pool *mp_api;
	enum ovpn_endpoint type;
	int mask;
};

struct ovpn_sess {
	struct mm_pool *mp;
	struct mm_pool *mp_api;
	struct aaa *aaa;
};

plugin_log_t ovpn_log = NULL;

static void 
ovpn_log_write(struct log_ctx *ctx, const char *msg, int len)
{
	char buf[4096] = {0};
	snprintf(buf, sizeof(buf) - 1, "%s:%s %s", ctx->module, ctx->fn, msg);
	if (ovpn_log)
		ovpn_log(PLOG_NOTE, "ssl", buf);
}

static const char *
envp_get(const char *name, const char *envp[])
{
	const int namelen = strlen (name);
	for (int i = 0; envp[i]; ++i) {
		if (!strncmp(envp[i], name, namelen)) {
			const char *cp = envp[i] + namelen;
			if (*cp == '=')
				return cp + 1;
		}
	}

	return NULL;
}

static void
envp_dbg(const char *envp[])
{
	for (int i = 0; envp[i]; ++i)
		debug4("%s", envp[i]);
}

EXPORT(int) 
openvpn_plugin_select_initialization_point_v1(void)
{
	return OPENVPN_PLUGIN_INIT_PRE_DAEMON;
}

EXPORT(int)
openvpn_plugin_min_version_required_v1(void)
{
	return OPENVPN_PLUGIN_VERSION;
}

EXPORT(void)
openvpn_plugin_close_v1(openvpn_plugin_handle_t handle)
{
	debug4("plugin close");
}

EXPORT(int)
openvpn_plugin_open_v3(const int version,
                       struct openvpn_plugin_args_open_in const *args,
                       struct openvpn_plugin_args_open_return *ret)
{
	struct mm_pool *mp = mm_pool_create(CPU_PAGE_SIZE, 0);
	struct ovpn_ctxt *ovpn = mm_pool_alloc(mp, sizeof(*ovpn));
	ovpn_log = args->callbacks->plugin_log;

	log_custom_set(ovpn_log_write, NULL);
	log_name("vpn");

	envp_dbg(args->envp);

	const char *protocol  = envp_get("openaaa_protocol", args->envp);
	const char *handler   = envp_get("openaaa_handler", args->envp);
	const char *authority = envp_get("openaaa_authority", args->envp);
	const char *verbose   = envp_get("openaaa_verbose", args->envp);
	const char *service   = envp_get("openaaa_service", args->envp);
	const char *group     = envp_get("openaaa_group", args->envp);
	const char *role      = envp_get("openaaa_role", args->envp);

	if (protocol)
		setenv("OPENAAA_PROTOCOL", protocol, 1);
	if (handler)
		setenv("OPENAAA_HANDLER", handler, 1);
	if (authority)
		setenv("OPENAAA_AUTHORITY", authority, 1);
	if (verbose)
		setenv("OPENAAA_VERBOSE", verbose, 1);
	if (service)
		setenv("OPENAAA_SERVICE", service, 1);
	if (group)
		setenv("OPENAAA_GROUP", group, 1);
	if (role)
		setenv("OPENAAA_ROLE", role, 1);

	ovpn->mp_api = mm_pool_create(CPU_PAGE_SIZE, 0);
	ovpn->mp = mp;
	ovpn->type = envp_get("remote_1", args->envp) ? VPN_CLIENT : VPN_SERVER;

	switch(ovpn->type) {
	case VPN_SERVER:
		debug1("setting up tls server");
		ovpn->mask |= OVPN_MASK(OPENVPN_PLUGIN_TLS_FINAL);
		ovpn->mask |= OVPN_MASK(OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY);
		break;
	case VPN_CLIENT:
		debug1("setting up tls client");
		ovpn->mask |= OVPN_MASK(OPENVPN_PLUGIN_CLIENT_CONNECT);
		ovpn->mask |= OVPN_MASK(OPENVPN_PLUGIN_CLIENT_DISCONNECT);
		ovpn->mask |= OVPN_MASK(OPENVPN_PLUGIN_ROUTE_UP);
		break;
	default:
		error("endpoint detection type failed");
		break;
	}

	ret->type_mask = ovpn->mask;
	ret->handle = (void *)ovpn;

	crypto_handshake_asynch(1);
	crypto_lookup();
	return OPENVPN_PLUGIN_FUNC_SUCCESS;
}


EXPORT(void *)
openvpn_plugin_client_constructor_v1(openvpn_plugin_handle_t handle)
{
	struct mm_pool *mp = mm_pool_create(CPU_PAGE_SIZE, 0);
	struct ovpn_ctxt *ovpn = (struct ovpn_ctxt *)handle;
        struct ovpn_sess *sess = mm_pool_alloc(mp, sizeof(*sess));

	sess->mp = mp;
        sess->mp_api = mm_pool_create(CPU_PAGE_SIZE, 0);

	if (ovpn->type == VPN_SERVER)
		sess->aaa = aaa_new(0,0);
	debug1("client constructor");
	return (void *)sess;
}

EXPORT(void)
openvpn_plugin_client_destructor_v1(openvpn_plugin_handle_t handle, void *ctx)
{
	//struct ovpn_ctxt *ovpn = (struct ovpn_ctxt *)handle;
	struct ovpn_sess *sess = (struct ovpn_sess *)ctx;

	if (sess->aaa)
		aaa_free(sess->aaa);

	mm_pool_destroy(sess->mp_api);
	mm_pool_destroy(sess->mp);
	debug1("client destructor");
}

static inline void
openvpn_auth_user_verify(const int version,
                         struct openvpn_plugin_args_func_in const *args,
                         struct openvpn_plugin_args_func_return *ret)
{
	const char *user = envp_get("username", args->envp);
	const char *pass = envp_get("password", args->envp);
	debug1("cred u: %s p: %s", user, pass);
}

static inline int
authz_group(struct aaa *aaa, const char *key, const char *g, const char *role)
{
	if (!g)
		return OPENVPN_PLUGIN_FUNC_ERROR;

	for (int i = 0; i < 10; i++) {
		aaa_reset(aaa);
		aaa_attr_set(aaa, "sess.id", key);
		aaa_bind(aaa);

		const char *uid = aaa_attr_get(aaa, "user.id");
		info("checking for user %s", uid ? "yes": "no");
		if (!uid || !*uid) {
			sleep(1);
			continue;
		}

		char *path = printfa("acct.%s.roles[]", g);
		const char *acct = aaa_attr_get(aaa, path);

		if (!acct || !*acct)
			return OPENVPN_PLUGIN_FUNC_ERROR;
		if (!role)
			return OPENVPN_PLUGIN_FUNC_SUCCESS;

		char *t, *ln = strdupa(acct);
		for (char *p = strtok_r(ln, ":", &t); p; 
		           p = strtok_r(NULL, ":", &t)) {
			if (!strcmp(role, p))
				return OPENVPN_PLUGIN_FUNC_SUCCESS;
		}


		return 0 ? OPENVPN_PLUGIN_FUNC_SUCCESS: 
		             OPENVPN_PLUGIN_FUNC_ERROR;

	}

	return OPENVPN_PLUGIN_FUNC_ERROR;
}

EXPORT(int)
openvpn_plugin_func_v3(const int version,
                       struct openvpn_plugin_args_func_in const *args,
                       struct openvpn_plugin_args_func_return *ret)
{
	struct ovpn_ctxt *ovpn = (struct ovpn_ctxt *)args->handle;
	struct ovpn_sess *sess = (struct ovpn_sess *)args->per_client_context;
	struct aaa *aaa = sess->aaa;

	switch(args->type) {
	case OPENVPN_PLUGIN_ENABLE_PF:
		debug1("enable pf");
		return OPENVPN_PLUGIN_FUNC_SUCCESS;
	case OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY:
		debug1("auth user_pass");
		openvpn_auth_user_verify(version, args, ret);
		return OPENVPN_PLUGIN_FUNC_SUCCESS;
	case OPENVPN_PLUGIN_ROUTE_UP:
		debug1("route up");
		return OPENVPN_PLUGIN_FUNC_SUCCESS;
	case OPENVPN_PLUGIN_CLIENT_CONNECT:
		debug1("connect");
		return OPENVPN_PLUGIN_FUNC_SUCCESS;
	case OPENVPN_PLUGIN_CLIENT_DISCONNECT:
		debug1("disconnect");
		return OPENVPN_PLUGIN_FUNC_SUCCESS;
	case OPENVPN_PLUGIN_TLS_VERIFY:
		debug1("tls verify");
		return OPENVPN_PLUGIN_FUNC_SUCCESS;
	case OPENVPN_PLUGIN_TLS_FINAL:
		if (ovpn->type != VPN_SERVER)
			return OPENVPN_PLUGIN_FUNC_SUCCESS;

		const char *key = envp_get(OVPN_ENV_EKM, args->envp);
		if (!key || !*key)
			return OPENVPN_PLUGIN_FUNC_ERROR;

		const char *group = envp_get("openaaa_group", args->envp);
		const char *role  = envp_get("openaaa_role", args->envp);

		return authz_group(aaa, key, group, role);
	default:
		goto failed;
	}

	return OPENVPN_PLUGIN_FUNC_SUCCESS; 

failed:	
	return OPENVPN_PLUGIN_FUNC_ERROR;
}
