
#include <jni.h>

void close(JNIEnv *env, jclass inputStreamClazz, jobject instance);

jbyteArray MD5(JNIEnv *env, jbyteArray data);

void NativeMD5(uint8_t *input, size_t inputLen, uint8_t *output);

jbyteArray NativeMD5(JNIEnv *env, jbyteArray data);

// bool ReadData(JNIEnv *env, jobject inputStream, jobject outputStream);
//
// jbyteArray ReadData(JNIEnv *env, jint size, jobject inputStream);
//
// jbyteArray ReadData(JNIEnv *env, jobject inputStream);
//
// jint ReadData(JNIEnv *env, jobject inputStream, jint len, jbyteArray buf);
//
// jbyteArray
// DESEncrypt(JNIEnv *env, jbyteArray data, jint dataOffset, jint dataLen, jbyteArray keyData,
//            jint keyOffset, jbyteArray ivData, jint ivOffset, jint ivLen);
//
// jbyteArray AESDecrypt(JNIEnv *env, jbyteArray data, jbyteArray keyData, jint offset, jint len,
//                       jbyteArray ivData);
//
// bool AESDecrypt(JNIEnv *env, jobject inputStream, jbyteArray keyData, jint offset, jint len,
//                 jbyteArray ivData, jobject outputStream);
