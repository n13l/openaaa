#define _GNU_SOURCE 1
//#define ENABLE_SSL

#include <sys/compiler.h>
#include <sys/cpu.h>
#include <sys/dll.h>
#include <mem/pool.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <modules/openvpn/plugin.h>

#define OVPN_MASK OPENVPN_PLUGIN_MASK

enum ovpn_endpoint { VPN_CLIENT, VPN_SERVER };

struct ovpn_ctxt {
	struct mm_pool *mp;
	struct mm_pool *mp_api;
	enum ovpn_endpoint type;
	plugin_log_t log;
	int mask;
};

struct ovpn_sess {
	struct mm_pool *mp;
	struct mm_pool *mp_api;
};

/*
static void
openplugin_sys_log(void *usr, unsigned level, const char *msg)
{
}
*/

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

/*
static void
envp_dbg(const char *envp[])
{
	for (int i = 0; envp[i]; ++i) {
		const char *cp = envp[i] + strlen(envp[i]);
		sys_dbg("envp: %s", envp[i]);
	}
	
}
*/

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
	sys_dbg("plugin close");
}

EXPORT(int)
openvpn_plugin_open_v3(const int version,
                       struct openvpn_plugin_args_open_in const *args,
                       struct openvpn_plugin_args_open_return *ret)
{
	struct mm_pool *mp = mm_pool_create(NULL, CPU_PAGE_SIZE, 0);
	struct ovpn_ctxt *ovpn = mm_alloc(mp, sizeof(*ovpn));

	ovpn->mp_api = mm_pool_create(NULL, CPU_PAGE_SIZE, 0);

	ovpn->mp = mp;
	ovpn->log = args->callbacks->plugin_log;
	ovpn->type = envp_get("remote_1", args->envp) ? VPN_CLIENT : VPN_SERVER;

	switch(ovpn->type) {
	case VPN_SERVER:
		sys_dbg("setting up tls server");
		ovpn->mask |= OVPN_MASK(OPENVPN_PLUGIN_TLS_FINAL);
		ovpn->mask |= OVPN_MASK(OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY);
		break;
	case VPN_CLIENT:
		sys_dbg("setting up tls client");
		ovpn->mask |= OVPN_MASK(OPENVPN_PLUGIN_CLIENT_CONNECT);
		ovpn->mask |= OVPN_MASK(OPENVPN_PLUGIN_CLIENT_DISCONNECT);
		ovpn->mask |= OVPN_MASK(OPENVPN_PLUGIN_ROUTE_UP);
		break;
	default:
		sys_err("endpoint detection type failed");
		break;
	}

	ret->type_mask = ovpn->mask;
	ret->handle = (void *)ovpn;
	return OPENVPN_PLUGIN_FUNC_SUCCESS;
}


EXPORT(void *)
openvpn_plugin_client_constructor_v1(openvpn_plugin_handle_t handle)
{
	struct mm_pool *mp = mm_pool_create(NULL, CPU_PAGE_SIZE, 0);

	//struct ovpn_ctxt *ovpn = (struct ovpn_ctxt *)handle;
        struct ovpn_sess *sess = mm_alloc(mp, sizeof(*sess));

	sess->mp = mp;
        sess->mp_api = mm_pool_create(NULL, CPU_PAGE_SIZE, 0);
	sys_dbg("client constructor");
	return (void *)sess;
}

EXPORT(void)
openvpn_plugin_client_destructor_v1(openvpn_plugin_handle_t handle, void *ctx)
{
	//struct ovpn_ctxt *ovpn = (struct ovpn_ctxt *)handle;
	struct ovpn_sess *sess = (struct ovpn_sess *)ctx;

	mm_destroy(sess->mp_api);
	mm_destroy(sess->mp);
	sys_dbg("client destructor");
}

static inline void
openvpn_auth_user_verify(const int version,
                         struct openvpn_plugin_args_func_in const *args,
                         struct openvpn_plugin_args_func_return *ret)
{
	//const char *user = envp_get("username", args->envp);
	//const char *pass = envp_get("password", args->envp);

	//sys_dbg("auth user=%s pass=%s", user, pass);
}

EXPORT(int)
openvpn_plugin_func_v3(const int version,
                       struct openvpn_plugin_args_func_in const *args,
                       struct openvpn_plugin_args_func_return *ret)
{
	//struct ovpn_ctxt *ovpn = (struct ovpn_ctxt *)args->handle;
	//struct ovpn_sess *sess = (struct ovpn_sess *)args->per_client_context;

	switch(args->type) {
	case OPENVPN_PLUGIN_ENABLE_PF:
		sys_dbg("enable pf");
		return OPENVPN_PLUGIN_FUNC_SUCCESS;
	case OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY:
		sys_dbg("auth user_pass");
		openvpn_auth_user_verify(version, args, ret);
		return OPENVPN_PLUGIN_FUNC_SUCCESS;
	case OPENVPN_PLUGIN_ROUTE_UP:
		sys_dbg("route up");
		return OPENVPN_PLUGIN_FUNC_SUCCESS;
	case OPENVPN_PLUGIN_CLIENT_CONNECT:
		sys_dbg("connect");
		return OPENVPN_PLUGIN_FUNC_SUCCESS;
	case OPENVPN_PLUGIN_CLIENT_DISCONNECT:
		sys_dbg("disconnect");
		return OPENVPN_PLUGIN_FUNC_SUCCESS;
	case OPENVPN_PLUGIN_TLS_VERIFY:
		sys_dbg("tls verify");
		return OPENVPN_PLUGIN_FUNC_SUCCESS;
	case OPENVPN_PLUGIN_TLS_FINAL:
		sys_dbg("aaa tls server authentication");
		return OPENVPN_PLUGIN_FUNC_SUCCESS;
	default:
		goto failed;
	}

	return OPENVPN_PLUGIN_FUNC_SUCCESS; 

failed:	
	return OPENVPN_PLUGIN_FUNC_ERROR;
}
