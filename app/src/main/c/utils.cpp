

#include "utils.h"
#include "md5.h"
#include "jni.h"

void close(JNIEnv *env, jclass inputStreamClazz, jobject instance) {
    env->CallVoidMethod(instance, env->GetMethodID(inputStreamClazz, "close", "()V"));
    if (env->ExceptionCheck()) {
        //throw IOException
        env->ExceptionDescribe();
        env->ExceptionClear();
    }
}

jbyteArray MD5(JNIEnv *env, jbyteArray data) {
    jbyteArray out = NULL;
    jclass messageDigestClass = env->FindClass("java/security/MessageDigest");
    jmethodID getInstanceId = env->GetStaticMethodID(messageDigestClass, "getInstance",
                                                     "(Ljava/lang/String;)Ljava/security/MessageDigest;");
    jstring md5 = env->NewStringUTF("MD5");
    jobject messageDigest = env->CallStaticObjectMethod(messageDigestClass, getInstanceId, md5);
    env->DeleteLocalRef(md5);

    // jmethodID updateId = env->GetMethodID(messageDigestClass, "update", "([B)V");
    // env->CallVoidMethod(messageDigest, updateId, data);

    out = (jbyteArray) env->CallObjectMethod(messageDigest,
                                             env->GetMethodID(messageDigestClass, "digest",
                                                              "([B)[B"),
                                             data);
    env->DeleteLocalRef(messageDigest);
    return out;
}


/**
 * output:长度16字节
 */
void NativeMD5(uint8_t *input, uint32_t inputLen, uint8_t *output) {
    MD5_CTX context = {0};
    MD5Init(&context);
    MD5Update(&context, input, inputLen);
    MD5Final(output, &context);

    //test*************************
    /*const char TABLE[] = {'0', '1', '2', '3',
                          '4', '5', '6', '7',
                          '8', '9', 'a', 'b',
                          'c', 'd', 'e', 'f'};
    std::string md5;
    for(int i = 0; i < 16; i++)
    {
        md5.push_back(TABLE[output[i] >> 4]);
        md5.push_back(TABLE[output[i] & 0x0F]);
    }
    LOG("md5 %s", md5.c_str());*/
    //test*************************
}

jbyteArray NativeMD5(JNIEnv *env, jbyteArray data) {
    jbyteArray out = NULL;

    jbyte *arr = env->GetByteArrayElements(data, 0);
    if (arr) {
        jsize len = env->GetArrayLength(data);
#define MD5_LEN 16
        uint8_t dest[MD5_LEN] = {0};
        NativeMD5((uint8_t *) arr, (uint32_t) len, dest);
        //释放对象
        env->ReleaseByteArrayElements(data, arr, 0);

        out = env->NewByteArray(MD5_LEN);
        env->SetByteArrayRegion(out, 0, MD5_LEN, (jbyte *) dest);

        //test*************************
        /*const char *a = "";
        NativeMD5((uint8_t *)a, (uint32_t)strlen(a), dest);//d41d8cd98f00b204e9800998ecf8427e
        const char *b = "a";
        NativeMD5((uint8_t *)b, (uint32_t)strlen(b), dest);//0cc175b9c0f1b6a831c399e269772661
        const char *c = "abc";
        NativeMD5((uint8_t *)c, (uint32_t)strlen(c), dest);//900150983cd24fb0d6963f7d28e17f72
        const char *d = "message digest";
        NativeMD5((uint8_t *)d, (uint32_t)strlen(d), dest);//f96b697d7cb7938d525a2f31aaf161d0
        const char *e = "abcdefghijklmnopqrstuvwxyz";
        NativeMD5((uint8_t *)e, (uint32_t)strlen(e), dest);//c3fcd3d76192e4007dfb496cca67e13b
        const char *f = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        NativeMD5((uint8_t *)f, (uint32_t)strlen(f), dest);//d174ab98d277d9f5a5611c2c9f419d9f
        const char *g = "12345678901234567890123456789012345678901234567890123456789012345678901234567890";
        NativeMD5((uint8_t *)g, (uint32_t)strlen(g), dest);//57edf4a22be3c955ac49da2e2107b67a*/
        //test**************************
    }

    return out;
}
