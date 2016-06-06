#include <windows.h>
#include <shlwapi.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>
#include "err.h"

void *
proc_self(void)
{
	return NULL;
}

struct tm *localtime_r(const time_t *timep, struct tm *result)
{
	struct tm *res = localtime(timep);
	memcpy(result, res, sizeof(*res));
	return result;
}

struct reg {
	char path[MAX_PATH];
	char name[MAX_PATH];
	char value[MAX_PATH];
	DWORD type;
	DWORD size;
};

struct uri_scheme {
	char id[MAX_PATH];
	char handler[MAX_PATH];
	char about[MAX_PATH];
};

#define ERROR_FMT FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS

void
sys_call_error(char *func)
{
	LPTSTR err = NULL;
	DWORD dw = GetLastError();
	WORD lang = MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT);

	if (FormatMessage(ERROR_FMT,NULL,dw, lang, err, 0, NULL ))
		fprintf(stderr, "FormatMessage() failed");

	fprintf(stderr, "%d %s", (int)dw, (char *)err);
	if (err)
		LocalFree(err);
}

static int
uri_scheme_check(struct uri_scheme *u)
{
        HKEY key = NULL;
	DWORD size = MAX_PATH, type;
	int err = 0;

        sys_call(RegOpenKeyEx,    ERROR_SUCCESS, HKEY_CLASSES_ROOT, u->id, 0, KEY_READ, &key);
        sys_call(RegQueryValueEx, ERROR_SUCCESS, key, "URL Protocol", 0, &type, (LPBYTE)u->about, &size);

        size = MAX_PATH;
        sys_call(RegQueryValueEx, ERROR_SUCCESS, key, NULL, 0, &type, (LPBYTE)u->about, &size);

	if (type != REG_SZ && type != REG_MULTI_SZ)
		goto sys_error;

	err = 1;
sys_error:
	if (key)
		RegCloseKey(key);
	return err;
}

static int
uri_scheme_parse(struct uri_scheme *uri_scheme)
{
	return 0;
}

static int
uri_scheme_name(const char *name)
{
	HKEY key = NULL;
	struct reg reg;

	sys_call(RegOpenKeyEx, ERROR_SUCCESS, HKEY_CLASSES_ROOT, name, 0, KEY_READ, &key);

	reg.size = sizeof(reg.value);
	if (RegQueryValueEx(key, "URL Protocol", 0, &reg. type, (LPBYTE)reg.value, &reg.size) != ERROR_SUCCESS)
		goto exit;

	if (reg.type != REG_SZ && reg.type != REG_MULTI_SZ)
		goto exit;

	reg.size = sizeof(reg.value);
	if (RegQueryValueEx(key, NULL, 0, &reg.type, (LPBYTE)reg.value, &reg.size) != ERROR_SUCCESS)
		goto exit;

	if (reg.type != REG_SZ && reg.type != REG_MULTI_SZ)
		goto exit;

	RegCloseKey(key);
	key = NULL;

	reg.size = sizeof(reg.path);
	snprintf(reg.path, reg.size, "%s\\shell\\open\\command", name);
	if (RegOpenKeyEx(HKEY_CLASSES_ROOT, reg.path, 0, KEY_READ, &key) != ERROR_SUCCESS)
		return 0;

	reg.size = sizeof(reg.value);
	if (RegQueryValueEx(key, NULL, 0, &reg.type, (LPBYTE)reg.value, &reg.size) != ERROR_SUCCESS)
		goto exit;

	if (reg.type != REG_SZ && reg.type != REG_MULTI_SZ)
		goto exit;

	printf("%-16s\t%s\n", name, reg.value);

sys_error:
exit:
	if (key)
		RegCloseKey(key);

	return 0;
}

static int
uri_scheme_index(unsigned int i)
{
	char name[4096] = {0};
	DWORD size = sizeof(name);

	sys_call(SHEnumKeyEx, ERROR_SUCCESS, HKEY_CLASSES_ROOT, i, name, &size);
	uri_scheme_name(name);

	return 0;
sys_error:
	return 1;
}

void
sys_uri_scheme_dump(const char *name)
{
	if (name)
		uri_scheme_name(name);
	else
		for (int i = 0; uri_scheme_index(i) == 0; i++);
}

int
sys_uri_scheme_register(const char *id, const char *handler, const char *about)
{
	struct uri_scheme arg;
	memset(&arg, 0, sizeof(arg));

	if (!id || !*id || !handler || !*handler || !about || !*about)
		return -EINVAL;

	strncpy(arg.id, id, sizeof(arg.id) - 1);
	strncpy(arg.handler, handler, sizeof(arg.handler) - 1);
	strncpy(arg.about, about, sizeof(arg.about) - 1);

	if (uri_scheme_check(&arg)) {
		fprintf(stderr, "uri::scheme %s is allready registered\n", id);
		return -EINVAL;
	}

	HKEY key = NULL;
	sys_call(RegCreateKeyEx, ERROR_SUCCESS, HKEY_CLASSES_ROOT, id, 0L, NULL, 
	         REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &key, NULL );

	sys_call(RegSetValueEx, ERROR_SUCCESS, key, NULL, 0, REG_SZ, about, strlen(about));
	sys_call(RegSetValueEx, ERROR_SUCCESS, key, "URL Protocol", 0, REG_SZ, "", 0);
	sys_call(RegFlushKey,   ERROR_SUCCESS, key);

	RegCloseKey(key);
	key = NULL;

	char path[MAX_PATH];
        DWORD size = sizeof(path);
        snprintf(path, size, "%s\\shell\\open\\command", id);

        sys_call(RegCreateKeyEx, ERROR_SUCCESS, HKEY_CLASSES_ROOT, path, 0L, NULL,
                 REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &key, NULL );
	sys_call(RegSetValueEx, ERROR_SUCCESS, key, NULL, 0, REG_SZ, handler, strlen(handler));
	sys_call(RegFlushKey,   ERROR_SUCCESS, key);

sys_error:
	if (key)
		RegCloseKey(key);

	return 0;
}

int
sys_uri_scheme_unregister(const char *id)
{
	struct uri_scheme arg;
	memset(&arg, 0, sizeof(arg));

        if (!id || !*id)
                return -EINVAL;

        strncpy(arg.id, id, sizeof(arg.id) - 1);

        if (!uri_scheme_check(&arg)) {
                fprintf(stderr, "uri::scheme %s not found\n", id);
                return -EINVAL;
        }

	HKEY key;
	sys_call_trace(RegOpenKeyEx, ERROR_SUCCESS, HKEY_CLASSES_ROOT, id, 0, KEY_READ, &key);
	sys_call_trace(SHDeleteKey, ERROR_SUCCESS, HKEY_CLASSES_ROOT, id);
sys_error:
	if (key)
		RegCloseKey(key);
	return 0;
}


