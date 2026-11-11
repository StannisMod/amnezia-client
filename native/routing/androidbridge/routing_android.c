//go:build android && cgo && amnezia_android_bridge

#include <jni.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include "_cgo_export.h"
#include "routing_host.h"

struct routing_host {
    JavaVM *vm;
    jobject callback;
    jmethodID protect;
    jmethodID protect_interface;
    jmethodID interfaces;
    jmethodID owner;
};

int amnezia_routing_has_owner(uintptr_t token) {
    return ((struct routing_host *)token)->owner != NULL;
}

static JNIEnv *host_env(struct routing_host *host, int *attached) {
    JNIEnv *env = NULL;
    *attached = 0;
    jint result = (*host->vm)->GetEnv(host->vm, (void **)&env, JNI_VERSION_1_6);
    if (result == JNI_EDETACHED) {
        if ((*host->vm)->AttachCurrentThread(host->vm, &env, NULL) != JNI_OK) return NULL;
        *attached = 1;
    } else if (result != JNI_OK) return NULL;
    return env;
}

int amnezia_routing_protect(uintptr_t token, int fd) {
    struct routing_host *host = (struct routing_host *)token;
    int attached;
    JNIEnv *env = host_env(host, &attached);
    if (!env) return 0;
    jboolean ok = (*env)->CallBooleanMethod(env, host->callback, host->protect, fd);
    if ((*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); ok = JNI_FALSE; }
    if (attached) (*host->vm)->DetachCurrentThread(host->vm);
    return ok == JNI_TRUE;
}

int amnezia_routing_owner(uintptr_t token, int protocol, const char *source, int source_port, const char *destination, int destination_port) {
    struct routing_host *host = (struct routing_host *)token;
    if (!host->owner) return -1;
    int attached;
    JNIEnv *env = host_env(host, &attached);
    if (!env) return -1;
    jstring src = (*env)->NewStringUTF(env, source);
    jstring dst = src ? (*env)->NewStringUTF(env, destination) : NULL;
    jint uid = -1;
    if (src && dst) uid = (*env)->CallIntMethod(env, host->callback, host->owner, protocol, src, source_port, dst, destination_port);
    if ((*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); uid = -1; }
    if (src) (*env)->DeleteLocalRef(env, src);
    if (dst) (*env)->DeleteLocalRef(env, dst);
    if (attached) (*host->vm)->DetachCurrentThread(host->vm);
    return uid;
}

char *amnezia_routing_interfaces(uintptr_t token) {
    struct routing_host *host = (struct routing_host *)token;
    int attached;
    JNIEnv *env = host_env(host, &attached);
    if (!env) return NULL;
    char *result = NULL;
    jbyteArray bytes = (*env)->CallObjectMethod(env, host->callback, host->interfaces);
    if ((*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); bytes = NULL; }
    if (bytes) {
        jsize len = (*env)->GetArrayLength(env, bytes);
        result = calloc((size_t)len + 1, 1);
        if (result) (*env)->GetByteArrayRegion(env, bytes, 0, len, (jbyte *)result);
        if ((*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); free(result); result = NULL; }
        (*env)->DeleteLocalRef(env, bytes);
    }
    if (attached) (*host->vm)->DetachCurrentThread(host->vm);
    return result;
}

int amnezia_routing_protect_interface(uintptr_t token,int fd,const char *name) {
    struct routing_host *host=(struct routing_host *)token;
    int attached;JNIEnv *env=host_env(host,&attached);if(!env)return 0;
    jstring iface=(*env)->NewStringUTF(env,name);jboolean ok=JNI_FALSE;
    if(iface){ok=(*env)->CallBooleanMethod(env,host->callback,host->protect_interface,fd,iface);(*env)->DeleteLocalRef(env,iface);}
    if((*env)->ExceptionCheck(env)){(*env)->ExceptionClear(env);ok=JNI_FALSE;}
    if(attached)(*host->vm)->DetachCurrentThread(host->vm);
    return ok==JNI_TRUE;
}

void amnezia_routing_release(uintptr_t token) {
    struct routing_host *host = (struct routing_host *)token;
    if (!host) return;
    int attached;
    JNIEnv *env = host_env(host, &attached);
    if (env) {
        (*env)->DeleteGlobalRef(env, host->callback);
        if (attached) (*host->vm)->DetachCurrentThread(host->vm);
    }
    free(host);
}

JNIEXPORT jboolean JNICALL Java_org_amnezia_awg_RoutingBackend_validate(JNIEnv *env, jobject self, jbyteArray config) {
    if (!config) return JNI_FALSE;
    jsize len = (*env)->GetArrayLength(env, config);
    jbyte *bytes = (*env)->GetByteArrayElements(env, config, NULL);
    if (!bytes) return JNI_FALSE;
    jboolean valid = RoutingValidate((GoString){(const char *)bytes, len}) ? JNI_TRUE : JNI_FALSE;
    (*env)->ReleaseByteArrayElements(env, config, bytes, JNI_ABORT);
    return valid;
}

JNIEXPORT jlong JNICALL Java_org_amnezia_awg_RoutingBackend_start(JNIEnv *env, jobject self, jint fd, jbyteArray config, jobject callback) {
    if (!config || !callback) { if (fd >= 0) close(fd); return -1; }
    struct routing_host *host = calloc(1, sizeof(*host));
    if (!host) { close(fd); return -1; }
    if ((*env)->GetJavaVM(env, &host->vm) != JNI_OK) { free(host); close(fd); return -1; }
    host->callback = (*env)->NewGlobalRef(env, callback);
    if (!host->callback) {
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        free(host); close(fd); return -1;
    }
    jclass cls = (*env)->GetObjectClass(env, callback);
    if (!cls) {
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        amnezia_routing_release((uintptr_t)host); close(fd); return -1;
    }
    host->protect = (*env)->GetMethodID(env, cls, "protectSocket", "(I)Z");
    if (!(*env)->ExceptionCheck(env))
        host->protect_interface=(*env)->GetMethodID(env,cls,"protectSocketOnInterface","(ILjava/lang/String;)Z");
    if (!(*env)->ExceptionCheck(env))
        host->interfaces = (*env)->GetMethodID(env, cls, "interfacesJson", "()[B");
    // Optional for compatibility with packaged hosts predating per-app policy.
    if (!(*env)->ExceptionCheck(env)) {
        host->owner = (*env)->GetMethodID(env, cls, "connectionOwnerUid", "(ILjava/lang/String;ILjava/lang/String;I)I");
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    }
    (*env)->DeleteLocalRef(env, cls);
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    if (!host->callback || !host->protect || !host->protect_interface || !host->interfaces) {
        amnezia_routing_release((uintptr_t)host); close(fd); return -1;
    }
    jsize len = (*env)->GetArrayLength(env, config);
    jbyte *bytes = (*env)->GetByteArrayElements(env, config, NULL);
    if (!bytes) { amnezia_routing_release((uintptr_t)host); close(fd); return -1; }
    // RoutingStart always consumes both the FD and the host global reference.
    jlong handle = RoutingStart(fd, (GoString){(const char *)bytes, len}, (uintptr_t)host);
    (*env)->ReleaseByteArrayElements(env, config, bytes, JNI_ABORT);
    return handle;
}

JNIEXPORT void JNICALL Java_org_amnezia_awg_RoutingBackend_stop(JNIEnv *env, jobject self, jlong handle) {
    RoutingStop(handle);
}

JNIEXPORT jlongArray JNICALL Java_org_amnezia_awg_RoutingBackend_stats(JNIEnv *env, jobject self, jlong handle) {
    long long rx = 0, tx = 0, handshake = 0;
    if (RoutingReadStats(handle, &rx, &tx, &handshake) != 0) return NULL;
    jlong values[3] = {rx, tx, handshake};
    jlongArray result = (*env)->NewLongArray(env, 3);
    if (result) (*env)->SetLongArrayRegion(env, result, 0, 3, values);
    return result;
}

JNIEXPORT jbyteArray JNICALL Java_org_amnezia_awg_RoutingBackend_diagnostics(JNIEnv *env, jobject self, jlong handle) {
    char *json = RoutingDiagnostics(handle);
    if (!json) return NULL;
    jsize size = (jsize)strlen(json);
    jbyteArray result = (*env)->NewByteArray(env, size);
    if (result) (*env)->SetByteArrayRegion(env, result, 0, size, (jbyte *)json);
    free(json);
    return result;
}

JNIEXPORT jbyteArray JNICALL Java_org_amnezia_awg_RoutingBackend_buildInfo(JNIEnv *env, jobject self) {
    char *raw=RoutingBuildInfoJSON();if(!raw)return NULL;
    size_t size=strlen(raw);jbyteArray bytes=(*env)->NewByteArray(env,(jsize)size);
    if(bytes)(*env)->SetByteArrayRegion(env,bytes,0,(jsize)size,(const jbyte*)raw);
    free(raw);return bytes;
}

JNIEXPORT jboolean JNICALL Java_org_amnezia_awg_RoutingBackend_refresh(JNIEnv *env,jobject self,jlong handle,jstring endpoint,jboolean reopen) {
 const char *text=endpoint?(*env)->GetStringUTFChars(env,endpoint,NULL):NULL;
 if(endpoint&&!text)return JNI_FALSE;
 GoString target={text?text:"",text?(ptrdiff_t)strlen(text):0};
 int ok=RoutingRefresh(handle,target,reopen?1:0);
 if(text)(*env)->ReleaseStringUTFChars(env,endpoint,text);
 return ok?JNI_TRUE:JNI_FALSE;
}
JNIEXPORT jboolean JNICALL Java_org_amnezia_awg_RoutingBackend_reloadNetworkDns(JNIEnv *env,jobject self,jlong handle,jbyteArray snapshot) {
 if(!snapshot)return JNI_FALSE;
 jsize len=(*env)->GetArrayLength(env,snapshot);
 jbyte *bytes=(*env)->GetByteArrayElements(env,snapshot,NULL);if(!bytes)return JNI_FALSE;
 int ok=RoutingReloadDNS(handle,(GoString){(const char*)bytes,len});
 (*env)->ReleaseByteArrayElements(env,snapshot,bytes,JNI_ABORT);
 return ok?JNI_TRUE:JNI_FALSE;
}
JNIEXPORT void JNICALL Java_org_amnezia_awg_RoutingBackend_suspendNetworkDns(JNIEnv *env,jobject self,jlong handle) {
 RoutingSuspendDNS(handle);
}
