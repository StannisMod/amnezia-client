//go:build android && cgo && amnezia_android_bridge

#include <jni.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include "_cgo_export.h"
#include "routing_host.h"

struct routing_host {
    JavaVM *vm;
    jobject callback;
    jmethodID protect;
    jmethodID interfaces;
};

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
        host->interfaces = (*env)->GetMethodID(env, cls, "interfacesJson", "()[B");
    (*env)->DeleteLocalRef(env, cls);
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    if (!host->callback || !host->protect || !host->interfaces) {
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
