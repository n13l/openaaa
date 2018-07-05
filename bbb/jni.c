#include <sys/compiler.h>
#include <sys/log.h>
#include <stdlib.h>
#include <stdint.h>
#include <jni.h>
#include <mem/alloc.h>
#include <mem/pool.h>
#include <mem/page.h>

struct jalloc {
	jbyteArray jba;
	jobject ref;
};

static JavaVM *jvm = 0;

JNIEXPORT jint JNICALL 
JNI_OnLoad(JavaVM *jv, void *reserved)
{
	debug3("jni:onload()");
	jvm = jv;
	return JNI_VERSION_1_2;
}

JNIEXPORT void JNICALL
JNI_OnUnload(JavaVM *vm, void *reserved)
{
	debug3("jni:unload()");
	return;
}

JNIEnv *
jnu_get_env(void)
{
	JNIEnv *env;

	jint rc = (*jvm)->GetEnv(jvm, (void **)&env, JNI_VERSION_1_2);

	if (rc == JNI_EDETACHED)
		error("jni: current thread not attached");
	if (rc == JNI_EVERSION)
		error("jni: version not supported");
	return env;
}
