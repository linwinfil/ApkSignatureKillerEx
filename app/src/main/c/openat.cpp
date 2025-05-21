//
// Created by Thom on 2019/3/30.
//

#include <unistd.h>
#include <sys/syscall.h>
#include "openat.h"
#include <jni.h>
#include <android/log.h>
#include <cstring>
#include "utils.h"
#include "md5.h"

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

const char *expectedMd5Hex = "3bf8931788824c6a1f2c6f6ff80f6b21";


intptr_t openAt(intptr_t fd, const char *path, intptr_t flag) {
#if defined(__arm__)
    intptr_t r;
    asm volatile(
#ifndef OPTIMIZE_ASM
    "mov r0, %1\n\t"
    "mov r1, %2\n\t"
    "mov r2, %3\n\t"
#endif

    "mov ip, r7\n\t"
    ".cfi_register r7, ip\n\t"
    "mov r7, #" STR(__NR_openat) "\n\t"
    "svc #0\n\t"
    "mov r7, ip\n\t"
    ".cfi_restore r7\n\t"

#ifndef OPTIMIZE_ASM
    "mov %0, r0\n\t"
#endif
    : "=r" (r)
    : "r" (fd), "r" (path), "r" (flag));
    return r;
#elif defined(__aarch64__)
    intptr_t r;
    asm volatile(
#ifndef OPTIMIZE_ASM
    "mov x0, %1\n\t"
    "mov x1, %2\n\t"
    "mov x2, %3\n\t"
#endif

    "mov x8, #" STR(__NR_openat) "\n\t"
    "svc #0\n\t"

#ifndef OPTIMIZE_ASM
    "mov %0, x0\n\t"
#endif
    : "=r" (r)
    : "r" (fd), "r" (path), "r" (flag));
    return r;
#else
    return (intptr_t) syscall(__NR_openat, fd, path, flag);
#endif
}

extern "C"
JNIEXPORT jint JNICALL
Java_bin_mt_test_MainActivity_openAt(JNIEnv *env, __attribute__((unused)) jclass clazz,
                                     jstring path) {
    const char *p = env->GetStringUTFChars(path, 0);
    __android_log_print(ANDROID_LOG_INFO, "openAt", "path=%s", p);
    intptr_t fd = openAt(AT_FDCWD, p, O_RDONLY);
    return fd;
}
extern "C"
JNIEXPORT jbyteArray JNICALL
Java_bin_mt_test_MainActivity_svc(JNIEnv *env, jclass clazz, jobject context) {
    // 获取Context的getPackageResourcePath方法
    jclass contextClass = env->GetObjectClass(context);
    jmethodID getPackageResourcePathMethod = env->GetMethodID(contextClass,
                                                              "getPackageResourcePath",
                                                              "()Ljava/lang/String;");

    // 调用getPackageResourcePath获取APK路径
    jstring apkPath = (jstring) env->CallObjectMethod(context, getPackageResourcePathMethod);


    // 打开APK文件
    const char *path = env->GetStringUTFChars(apkPath, 0);
    __android_log_print(ANDROID_LOG_INFO, "svc", "path=%s", path);
    intptr_t fd = openAt(AT_FDCWD, path, O_RDONLY);

    if (fd < 0) {
        __android_log_print(ANDROID_LOG_ERROR, "svc", "Failed to open APK file");
        return NULL;
    }

    // 获取ParcelFileDescriptor类
    jclass parcelFileDescriptorClass = env->FindClass("android/os/ParcelFileDescriptor");

    // 获取adoptFd方法
    jmethodID adoptFdMethod = env->GetStaticMethodID(parcelFileDescriptorClass, "adoptFd",
                                                     "(I)Landroid/os/ParcelFileDescriptor;");


    // 调用adoptFd方法获取ParcelFileDescriptor对象
    jobject parcelFd = env->CallStaticObjectMethod(parcelFileDescriptorClass, adoptFdMethod,
                                                   (jint) fd);


    jmethodID getFdMethod = env->GetMethodID(parcelFileDescriptorClass, "getFileDescriptor",
                                             "()Ljava/io/FileDescriptor;");


    jobject fdObj = env->CallObjectMethod(parcelFd, getFdMethod);


    // 创建FileInputStream对象
    jclass fileInputStreamClass = env->FindClass("java/io/FileInputStream");

    // 获取FileInputStream构造方法
    jmethodID fileInputStreamConstructor = env->GetMethodID(fileInputStreamClass, "<init>",
                                                            "(Ljava/io/FileDescriptor;)V");

    // 创建FileInputStream实例
    jobject fileInputStream = env->NewObject(fileInputStreamClass, fileInputStreamConstructor,
                                             fdObj);

    // 创建ZipInputStream对象
    jclass zipInputStreamClass = env->FindClass("java/util/zip/ZipInputStream");

    // 获取ZipInputStream构造方法
    jmethodID zipInputStreamConstructor = env->GetMethodID(zipInputStreamClass, "<init>",
                                                           "(Ljava/io/InputStream;)V");


    // 创建ZipInputStream实例
    jobject zipInputStream = env->NewObject(zipInputStreamClass, zipInputStreamConstructor,
                                            fileInputStream);


    // 获取ZipInputStream的getNextEntry方法
    jmethodID getNextEntryMethod = env->GetMethodID(zipInputStreamClass, "getNextEntry",
                                                    "()Ljava/util/zip/ZipEntry;");
    // 获取ZipEntry的getName方法
    jclass zipEntryClass = env->FindClass("java/util/zip/ZipEntry");
    jmethodID getNameMethod = env->GetMethodID(zipEntryClass, "getName", "()Ljava/lang/String;");

    // 遍历ZIP文件
    jobject entry;
    jbyteArray out = NULL;
    while ((entry = env->CallObjectMethod(zipInputStream, getNextEntryMethod)) != NULL) {
        // 获取文件名
        jstring entryName = (jstring) env->CallObjectMethod(entry, getNameMethod);
        const char *name = env->GetStringUTFChars(entryName, 0);

        // 检查是否是签名文件
        if (strstr(name, "META-INF/") == name &&
            (strstr(name, ".RSA") != NULL || strstr(name, ".DSA") != NULL ||
             strstr(name, ".EC") != NULL)) {

            // 获取CertificateFactory
            jclass certFactoryClass = env->FindClass("java/security/cert/CertificateFactory");
            // 获取getInstance方法
            jmethodID getInstanceMethod = env->GetStaticMethodID(certFactoryClass, "getInstance",
                                                                 "(Ljava/lang/String;)Ljava/security/cert/CertificateFactory;");

            // 创建CertificateFactory实例
            jstring certType = env->NewStringUTF("X509");
            jobject certFactory = env->CallStaticObjectMethod(certFactoryClass, getInstanceMethod,
                                                              certType);
            env->DeleteLocalRef(certType);


            // 获取generateCertificate方法
            jmethodID generateCertMethod = env->GetMethodID(certFactoryClass, "generateCertificate",
                                                            "(Ljava/io/InputStream;)Ljava/security/cert/Certificate;");
            // 生成证书
            jobject cert = env->CallObjectMethod(certFactory, generateCertMethod, zipInputStream);
            // 获取证书编码
            jmethodID getEncodedMethod = env->GetMethodID(env->GetObjectClass(cert), "getEncoded",
                                                          "()[B");
            jbyteArray encodedCert = (jbyteArray) env->CallObjectMethod(cert, getEncodedMethod);
            out = encodedCert;

            // 清理资源
            env->ReleaseStringUTFChars(entryName, name);
            env->DeleteLocalRef(entry);
            env->DeleteLocalRef(entryName);
            env->DeleteLocalRef(cert);
            env->DeleteLocalRef(certFactory);
            env->DeleteLocalRef(certFactoryClass);
            break;
        }

        env->ReleaseStringUTFChars(entryName, name);
        env->DeleteLocalRef(entry);
        env->DeleteLocalRef(entryName);
    }

    close(env, zipInputStreamClass, zipInputStream);
    close(env, fileInputStreamClass, fileInputStream);

    // 清理资源
    env->DeleteLocalRef(zipEntryClass);
    env->DeleteLocalRef(zipInputStream);
    env->DeleteLocalRef(fileInputStream);
    env->DeleteLocalRef(fdObj);
    env->DeleteLocalRef(parcelFd);
    env->ReleaseStringUTFChars(apkPath, path);

    return out;
}

extern "C"
JNIEXPORT jint JNICALL
Java_bin_mt_test_MainActivity_svce(JNIEnv *env, jclass clazz, jobject context) {
    jbyteArray encodedCertByteArray = Java_bin_mt_test_MainActivity_svc(env, clazz, context);

    // 避免上层hook md5的算法,改为使用底层md5
    jbyteArray signMd5Data = NativeMD5(env, encodedCertByteArray);
    // jbyteArray signMd5Data = MD5(env, encodedCert);

    // 将MD5字节数组转换为32位小写字符串
    jsize md5Length = env->GetArrayLength(signMd5Data);
    jbyte* md5Bytes = env->GetByteArrayElements(signMd5Data, NULL);

    const char hexDigits[] = "0123456789abcdef";
    char* md5Hex = new char[md5Length * 2 + 1];
    md5Hex[md5Length * 2] = '\0';
    int k = 0;
    for (int i = 0; i < md5Length; i++) {
        int b = md5Bytes[i] & 0xFF;
        md5Hex[k++] = hexDigits[(b >> 4) & 0x0F];
        md5Hex[k++] = hexDigits[b & 0x0F];
    }
    env->ReleaseByteArrayElements(signMd5Data, md5Bytes, 0);
    env->DeleteLocalRef(signMd5Data);
    __android_log_print(ANDROID_LOG_INFO, "svc", "native md5 hex:%s", md5Hex);
    if (strcmp(md5Hex, expectedMd5Hex) != 0) {
        // 抛出异常
        jclass exc = env->FindClass("java/lang/RuntimeException");
        env->ThrowNew(exc, "sign failed");
        return 0;
    } else {
        __android_log_print(ANDROID_LOG_INFO, "svc", "sign success");
    }
    return 1;
}


