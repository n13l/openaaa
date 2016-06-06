#include <sys/compiler.h>
#include <sys/log.h>
#include <stdlib.h>
#include <stdint.h>
#include <jni.h>

#include <sys/compiler.h>
#include <mem/alloc.h>
#include <mem/pool.h>
#include <mem/page.h>

#include <hotplug/prv.h>
#include <hotplug/jnu.h>
#include <hotplug/lib.h>

struct jalloc {
	jbyteArray jba;
	jobject ref;
};

static JavaVM *jvm = 0;

JNIEXPORT jint JNICALL 
JNI_OnLoad(JavaVM *jv, void *reserved)
{
	sys_dbg("jni:onload()");
	jvm = jv;
	return JNI_VERSION_1_2;
}

JNIEXPORT void JNICALL
JNI_OnUnload(JavaVM *vm, void *reserved)
{
	sys_dbg("jni:unload()");
	return;
}

JNIEnv *
jnu_get_env(void)
{
	JNIEnv *env;

	jint rc = (*jvm)->GetEnv(jvm, (void **)&env, JNI_VERSION_1_2);

	if (rc == JNI_EDETACHED)
		sys_dbg("java: current thread not attached");
	if (rc == JNI_EVERSION)
		sys_err("jni version not supported");
	return env;
}

void
jnu_set_jclass(void *ctx, const char *name)
{
	struct hotplug *hotplug = (struct hotplug *)ctx;
	hotplug->jclass = mp_strdup(hotplug->mp, name);
}

const char *
jnu_get_jclass(void *ctx)
{
	struct hotplug *hotplug = (struct hotplug *)ctx;
	return hotplug->jclass;
}
