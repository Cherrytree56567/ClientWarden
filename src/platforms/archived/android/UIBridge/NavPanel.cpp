#include <jni.h>
#include <string>
#include "CipherQuery/CipherQuery.h"
#include "GenericItem/GenericItem.h"
#include "LoginItem/LoginItem.h"
#include "Folder/Folder.h"
#include "Vault.h"
/*
jobject getClientwardenImageURL(JNIEnv* env, std::string url) {
    jclass uriClass = env->FindClass(
        "com/ct5/clientwarden/ClientwardenImage$Uri"
    );

    if (uriClass == nullptr) {
        return nullptr;
    }

    jmethodID constructor = env->GetMethodID(
        uriClass,
        "<init>",
        "(Ljava/lang/String;)V"
    );

    if (constructor == nullptr) {
        return nullptr;
    }

    jstring path = env->NewStringUTF(url.c_str());

    if (path == nullptr) {
        return nullptr;
    }

    jobject image = env->NewObject(
        uriClass,
        constructor,
        path
    );

    env->DeleteLocalRef(path);
    env->DeleteLocalRef(uriClass);

    return image;
}

jobject getLucideIcon(JNIEnv* env, std::string iconName) {
    jclass lucideClass = env->FindClass(
        "com/composables/icons/lucide/Lucide"
    );

    if (lucideClass == nullptr) {
        return nullptr;
    }

    jfieldID globeField = env->GetStaticFieldID(
        lucideClass,
        iconName.c_str(),
        "Landroidx/compose/ui/graphics/vector/ImageVector;"
    );

    if (globeField == nullptr) {
        return nullptr;
    }

    jobject globe = env->GetStaticObjectField(
        lucideClass,
        globeField
    );

    env->DeleteLocalRef(lucideClass);

    return globe;
}

jobject makeUuid(JNIEnv* env, std::string uuid)
{
    jclass uuidClass = env->FindClass("java/util/UUID");

    if (uuidClass == nullptr) {
        return nullptr;
    }

    jmethodID fromString = env->GetStaticMethodID(
        uuidClass,
        "fromString",
        "(Ljava/lang/String;)Ljava/util/UUID;"
    );

    if (fromString == nullptr) {
        return nullptr;
    }

    jstring uuidString = env->NewStringUTF(uuid.c_str());

    jobject result = env->CallStaticObjectMethod(
        uuidClass,
        fromString,
        uuidString
    );

    env->DeleteLocalRef(uuidString);
    env->DeleteLocalRef(uuidClass);

    return result;
}

jobject getItemType(JNIEnv* env, const std::string& typeName)
{
    jclass itemTypeClass = env->FindClass(
        "com/ct5/clientwarden/ItemType"
    );

    if (itemTypeClass == nullptr) {
        return nullptr;
    }

    jfieldID field = env->GetStaticFieldID(
        itemTypeClass,
        typeName.c_str(),
        "Lcom/ct5/clientwarden/ItemType;"
    );

    if (field == nullptr) {
        env->DeleteLocalRef(itemTypeClass);
        return nullptr;
    }

    jobject type = env->GetStaticObjectField(
        itemTypeClass,
        field
    );

    env->DeleteLocalRef(itemTypeClass);

    return type;
}

jobject makeItemList(JNIEnv* env, std::vector<jobject> items) {
    jclass arrayListClass = env->FindClass(
        "java/util/ArrayList"
    );

    if (arrayListClass == nullptr) {
        return nullptr;
    }

    jmethodID constructor = env->GetMethodID(
        arrayListClass,
        "<init>",
        "()V"
    );

    jobject list = env->NewObject(
        arrayListClass,
        constructor
    );

    jmethodID addMethod = env->GetMethodID(
        arrayListClass,
        "add",
        "(Ljava/lang/Object;)Z"
    );

    for (jobject item : items) {
        env->CallBooleanMethod(
            list,
            addMethod,
            item
        );
    }

    env->DeleteLocalRef(arrayListClass);

    return list;
}

jobject getItems(JNIEnv* env, std::vector<std::pair<ClientWarden::CipherType, std::string>> ciphers) {
    jclass itemClass =
        env->FindClass("com/ct5/clientwarden/ItemElement");

    jmethodID constructor = env->GetMethodID(
        itemClass,
        "<init>",
        "(Ljava/util/UUID;Ljava/lang/String;Lcom/ct5/clientwarden/ItemType;Landroidx/compose/ui/graphics/vector/ImageVector;)V"
    );

    try {
        ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

        std::vector<jobject> items;

        for (auto& cipher : ciphers) {
            jobject uuid = makeUuid(env, cipher.second);

            std::string c_name;

            v_inst.GetItem(cipher.second)
                 ->GetName(c_name)
                 ->Close();

            jstring name = env->NewStringUTF(name.c_str());

            jobject img = nullptr;

            if (cipher.first == ClientWarden::CipherType::Login) {
                std::vector<std::string> loginUrl;

                v_inst.GetItem<ClientWarden::LoginItem>(cipher.second)
                     ->GetWebsites(loginUrl)
                     ->Close();

                if (loginUrl.size() != 0) {
                    std::optional<std::string> result = v_inst.DownloadIcon(loginUrl[0]);
                    if (result.has_value()) {
                        img = getClientwardenImageURL(env, result.value());
                    } else {
                        img = getLucideIcon(env, "Globe");
                    }
                } else {
                    img = getLucideIcon(env, "Globe");
                }

                for (auto& uri : loginUrl) {
                    OPENSSL_cleanse(uri.data(), uri.size());
                    uri.clear();
                }
            } else if (cipher.first == ClientWarden::CipherType::Card) {
                img = getLucideIcon(env, "CreditCard");
            } else if (cipher.first == ClientWarden::CipherType::Identity) {
                img = getLucideIcon(env, "IdCard");
            } else if (cipher.first == ClientWarden::CipherType::Note) {
                img = getLucideIcon(env, "StickyNote");
            } else if (cipher.first == ClientWarden::CipherType::SSHKey) {
                img = getLucideIcon(env, "KeyRound");
            } else {
                img = getLucideIcon(env, "SquareDashed");
            }

            jobject i_type = nullptr;
            switch (cipher.first) {
                case ClientWarden::CipherType::Login:
                    i_type = getItemType("Login");
                    break;
                case ClientWarden::CipherType::Card:
                    i_type = getItemType("Card");
                    break;
                case ClientWarden::CipherType::Identity:
                    i_type = getItemType("Identity");
                    break;
                case ClientWarden::CipherType::Note:
                    i_type = getItemType("Note");
                    break;
                case ClientWarden::CipherType::SSHKey:
                    i_type = getItemType("SSH Key");
                    break;
                default:
                    i_type = getItemType("Login");
                    break;
            }

            jobject item = env->NewObject(
                itemClass,
                constructor,
                uuid,
                name,
                i_type,
                icon
            );

            items.push_back();
        }

        return makeItemList(env, items);
    } catch (...) {
        /*
         * TODO: Add TOAST
         *//*

        std::vector<jobject> items;
        return makeItemList(env, items);
    }
}

extern "C"
JNIEXPORT jobject JNICALL
Java_com_ct5_clientwarden_UIBridge_cb_allItems(JNIEnv* env, jobject _this) {
    try {
        ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

        std::vector<std::pair<ClientWarden::CipherType, std::string>> ciphers;
            
        ciphers = v_inst.GetCipherQuery()
                       ->FilterByUnbinned()
                        .FilterByUnarchived()
                        .GetCiphers();

        return getItems(env, ciphers);
    } catch (...) {
        /*
         * TODO: Add TOAST
         *//*

        std::vector<jobject> items;
        return makeItemList(env, items);
    }
}
*/