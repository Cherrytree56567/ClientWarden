#include <jni.h>
#include <string>
#include "Vault.h"

void setScreenType(JNIEnv* env, jobject _this, jint ordinal) {
    jclass loginScreenClass = env->FindClass("com/ct5/clientwarden/LoginScreen");
    if (loginScreenClass == nullptr) {
        return;
    }

    jfieldID instanceField = env->GetStaticFieldID(loginScreenClass, "INSTANCE", "Lcom/ct5/clientwarden/LoginScreen;");
    jobject instance = env->GetStaticObjectField(loginScreenClass, instanceField);

    jmethodID setter = env->GetMethodID(loginScreenClass, "setScreenType", "(I)V");
    env->CallVoidMethod(instance, setter, ordinal);

    env->DeleteLocalRef(loginScreenClass);
    env->DeleteLocalRef(instance);
}

void setMainActivityObjectType(JNIEnv* env, jobject _this, jint ordinal) {
    jclass mainActivityObjectClass = env->FindClass("com/ct5/clientwarden/MainActivityObject");
    if (mainActivityObjectClass == nullptr) {
        return;
    }

    jfieldID instanceField = env->GetStaticFieldID(mainActivityObjectClass, "INSTANCE", "Lcom/ct5/clientwarden/MainActivityObject;");
    jobject instance = env->GetStaticObjectField(mainActivityObjectClass, instanceField);

    jmethodID setter = env->GetMethodID(mainActivityObjectClass, "setScreenType", "(I)V");
    env->CallVoidMethod(instance, setter, ordinal);

    env->DeleteLocalRef(mainActivityObjectClass);
    env->DeleteLocalRef(instance);
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_ct5_clientwarden_UIBridge_cbLogin(JNIEnv* env, jobject _this, jstring j_username, jstring j_password,
    jstring j_vaultURL, jstring j_mainURL, jstring j_apiURL, jstring j_iconURL, jstring j_wssURL) {

    const char* c_username = (*env)->GetStringUTFChars(env, j_username, NULL);
    const char* c_password = (*env)->GetStringUTFChars(env, j_password, NULL);
    const char* c_vaultURL = (*env)->GetStringUTFChars(env, j_vaultURL, NULL);
    const char* c_mainURL = (*env)->GetStringUTFChars(env, j_mainURL, NULL);
    const char* c_apiURL = (*env)->GetStringUTFChars(env, j_apiURL, NULL);
    const char* c_iconURL = (*env)->GetStringUTFChars(env, j_iconURL, NULL);
    const char* c_wssURL = (*env)->GetStringUTFChars(env, j_wssURL, NULL);

    std::string username(c_username);
    std::string password(c_password);
    std::string vaultURL(c_vaultURL);
    std::string mainURL(c_mainURL);
    std::string apiURL(c_apiURL);
    std::string iconURL(c_iconURL);
    std::string wssURL(c_wssURL);

    (*env)->ReleaseStringUTFChars(env, j_username, c_username);
    (*env)->ReleaseStringUTFChars(env, j_password, c_password);
    (*env)->ReleaseStringUTFChars(env, j_vaultURL, c_vaultURL);
    (*env)->ReleaseStringUTFChars(env, j_mainURL, c_mainURL);
    (*env)->ReleaseStringUTFChars(env, j_apiURL, c_apiURL);
    (*env)->ReleaseStringUTFChars(env, j_iconURL, c_iconURL);
    (*env)->ReleaseStringUTFChars(env, j_wssURL, c_wssURL);
    
    ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

    v_inst.SetUris(vaultURL, mainURL, apiURL, iconURL, wssURL);

    bool result = v_inst.Login(email, password);

    if (!result) {
        /*
         * TODO: TOAST
        */
        return JNI_FALSE;
    }

    if (v_inst.state == ClientWarden::AuthState::WaitingForTOTP) {
        setScreenType(env, _this, 1);
        setMainActivityObjectType(env, _this, 0);
        return JNI_TRUE;
    } else if (v_inst.state == ClientWarden::AuthState::WaitingForDeviceVerif) {
        setScreenType(env, _this, 2);
        setMainActivityObjectType(env, _this, 0);
        return JNI_TRUE;
    } else if (v_inst.state == ClientWarden::AuthState::WaitingForPasskey) {
        /*
         * TODO: Passkey Login Support
         */
        return JNI_TRUE;
    }

    setMainActivityObjectType(env, _this, 2);

    return JNI_TRUE;
}