#include "SSHKeyItem.h"

namespace ClientWarden::Vault {
    SSHKeyItem::SSHKeyItem(Vault& vault, std::string uuid) : localVault(vault), isBeingCreated(false) {
        if (!logger) {
            logger = spdlog::stdout_color_mt("ClientWarden::Vault::SSHKeyItem");
        }
        if (!localVault.vaultData.contains("ciphers") || localVault.vaultData["ciphers"].is_null()) return;
        data["id"] = uuid;
        for (auto& cipher : localVault.vaultData["ciphers"]) {
            if (!cipher.contains("id")) {
                continue;
            }
            if (cipher["id"].get<std::string>() == uuid) {
                data = cipher;
                break;
            }
        }
        if (data.contains("data")) {
            if (data["data"].is_string()) {
                fieldData = nlohmann::json::parse(data["data"].get<std::string>());
            } else {
                fieldData = data["data"];
            }
        }
        if (data.contains("key")) {
            if (data["key"].is_null()) {
                itemEncKey = localVault.encKey;
                itemMacKey = localVault.macKey;
            } else  {
                auto keys = localVault.getKeysFromCipher(data["key"]);
                itemEncKey = keys.first;
                itemMacKey = keys.second;
            }
        } else {
            init = false;
        }
        init = false;
        if (data.contains("type")) {
            if (data["type"].get<int>() == 5) {
                init = true;
            }
        }
        if (!data.contains("sshKey")) {
            init = false;
        }
    }

    SSHKeyItem::SSHKeyItem(Vault& vault) : localVault(vault), isBeingCreated(true) {
        if (!logger) {
            logger = spdlog::stdout_color_mt("ClientWarden::Vault::SSHKeyItem");
        }
        auto keys = localVault.generateEncMacKeys();
        itemEncKey = keys.first;
        itemMacKey = keys.second;

        data["archivedDate"] = nullptr;
        data["attachments"] = nullptr;
        data["card"] = nullptr;
        data["collectionIds"] = nlohmann::json::array();
        data["creationDate"] = getBitwardenTime();
        data["data"] = "";
        data["deletedDate"] = nullptr;
        data["edit"] = true;
        data["favorite"] = false;
        data["fields"] = nlohmann::json::array();
        data["folderId"] = nullptr;
        data["id"] = uniqueGuid();
        data["identity"] = nullptr;
        std::vector<uint8_t> mainKey(itemEncKey.begin(), itemEncKey.end());
        mainKey.insert(mainKey.end(), itemMacKey.begin(), itemMacKey.end());
        data["key"] = localVault.InternalEncrypt(mainKey, localVault.encKey, localVault.macKey);
        OPENSSL_cleanse(mainKey.data(), mainKey.size());
        data["login"] = nullptr;
        data["name"] = localVault.Encrypt("", itemEncKey, itemMacKey);
        data["notes"] = nullptr;
        data["object"] = "cipherDetails";
        data["organizationId"] = nullptr;
        data["organizationUseTotp"] = false;
        data["passwordHistory"] = nullptr;
        data["permissions"] = nlohmann::json::object();
        data["permissions"]["delete"] = true;
        data["permissions"]["restore"] = true;
        data["reprompt"] = 0;
        data["revisionDate"] = nullptr;
        data["secureNote"] = nullptr;
        data["sshKey"] = nlohmann::json::object();
        data["sshKey"]["keyFingerprint"] = localVault.Encrypt("", itemEncKey, itemMacKey);
        data["sshKey"]["privateKey"] = localVault.Encrypt("", itemEncKey, itemMacKey);
        data["sshKey"]["publicKey"] = localVault.Encrypt("", itemEncKey, itemMacKey);
        data["type"] = 5;
        data["viewPassword"] = true;

        fieldData["PrivateKey"] = localVault.Encrypt("", itemEncKey, itemMacKey);
        fieldData["PublicKey"] = localVault.Encrypt("", itemEncKey, itemMacKey);
        fieldData["KeyFingerprint"] = localVault.Encrypt("", itemEncKey, itemMacKey);
        fieldData["Name"] = localVault.Encrypt("", itemEncKey, itemMacKey);
        fieldData["Notes"] = nullptr;
        fieldData["Fields"] = nlohmann::json::array();

        init = true;
    }

    SSHKeyItem::~SSHKeyItem() {
        /*
        * TODO: Destruct
        */
        OPENSSL_cleanse(itemEncKey.data(), itemEncKey.size());
        itemEncKey.clear();
        OPENSSL_cleanse(itemMacKey.data(), itemMacKey.size());
        itemMacKey.clear();
    }

    SSHKeyItem& SSHKeyItem::SetName(std::string& name) {
        if (!init) return *this;
        fieldData["Name"] = localVault.Encrypt(name, itemEncKey, itemMacKey);
        data["name"] = localVault.Encrypt(name, itemEncKey, itemMacKey);
        OPENSSL_cleanse(name.data(), name.size());
        name.clear();
        return *this;
    }

    SSHKeyItem& SSHKeyItem::SetFingerprint(std::string& fingerprint) {
        if (!init) return *this;
        if (!data.contains("sshKey") || !data["sshKey"].is_object()) return *this;
        fieldData["KeyFingerprint"] = localVault.Encrypt(fingerprint, itemEncKey, itemMacKey);
        data["sshKey"]["keyFingerprint"] = localVault.Encrypt(fingerprint, itemEncKey, itemMacKey);
        OPENSSL_cleanse(fingerprint.data(), fingerprint.size());
        fingerprint.clear();
        return *this;
    }

    SSHKeyItem& SSHKeyItem::SetPrivateKey(std::string& privateKey) {
        if (!init) return *this;
        if (!data.contains("sshKey") || !data["sshKey"].is_object()) return *this;
        fieldData["PrivateKey"] = localVault.Encrypt(privateKey, itemEncKey, itemMacKey);
        data["sshKey"]["privateKey"] = localVault.Encrypt(privateKey, itemEncKey, itemMacKey);
        OPENSSL_cleanse(privateKey.data(), privateKey.size());
        privateKey.clear();
        return *this;
    }

    SSHKeyItem& SSHKeyItem::SetPublicKey(std::string& publicKey) {
        if (!init) return *this;
        if (!data.contains("sshKey") || !data["sshKey"].is_object()) return *this;
        fieldData["PublicKey"] = localVault.Encrypt(publicKey, itemEncKey, itemMacKey);
        data["sshKey"]["publicKey"] = localVault.Encrypt(publicKey, itemEncKey, itemMacKey);
        OPENSSL_cleanse(publicKey.data(), publicKey.size());
        publicKey.clear();
        return *this;
    }

    SSHKeyItem& SSHKeyItem::SetNotes(std::string& notes) {
        if (!init) return *this;
        fieldData["Notes"] = localVault.Encrypt(notes, itemEncKey, itemMacKey);
        data["notes"] = localVault.Encrypt(notes, itemEncKey, itemMacKey);
        OPENSSL_cleanse(notes.data(), notes.size());
        notes.clear();
        return *this;
    }

    SSHKeyItem& SSHKeyItem::SetFolder(std::string folderUUID) {
        if (!init) return *this;
        data["folderId"] = folderUUID;
        return *this;
    }

    SSHKeyItem& SSHKeyItem::RemoveFolder() {
        if (!init) return *this;
        data["folderId"] = nullptr;
        return *this;
    }

    SSHKeyItem& SSHKeyItem::AddField(CustomFieldType field, std::string& name, std::string& value) {
        if (!init) return *this;
        if (!data.contains("fields") || !fieldData.contains("Fields")) return *this;
        if (fieldData["Fields"].is_null() || data["fields"].is_null()) {
            fieldData["Fields"] = nlohmann::json::object();
        }
        nlohmann::json addFieldData;
        nlohmann::json dataFieldData;
        if (field == CustomFieldType::Text) {
            addFieldData["linkedId"] = nullptr;
            addFieldData["name"] = localVault.Encrypt(name, itemEncKey, itemMacKey);
            addFieldData["type"] = 0;
            addFieldData["value"] = localVault.Encrypt(value, itemEncKey, itemMacKey);

            dataFieldData["Name"] = localVault.Encrypt(name, itemEncKey, itemMacKey);
            dataFieldData["Type"] = 0;
            dataFieldData["Value"] = localVault.Encrypt(value, itemEncKey, itemMacKey);
        } else if (field == CustomFieldType::Hidden) {
            addFieldData["linkedId"] = nullptr;
            addFieldData["name"] = localVault.Encrypt(name, itemEncKey, itemMacKey);
            addFieldData["type"] = 1;
            addFieldData["value"] = localVault.Encrypt(value, itemEncKey, itemMacKey);

            dataFieldData["Name"] = localVault.Encrypt(name, itemEncKey, itemMacKey);
            dataFieldData["Type"] = 1;
            dataFieldData["Value"] = localVault.Encrypt(value, itemEncKey, itemMacKey);
        } else if (field == CustomFieldType::Checkbox) {
            addFieldData["linkedId"] = nullptr;
            addFieldData["name"] = localVault.Encrypt(name, itemEncKey, itemMacKey);
            addFieldData["type"] = 2;
            addFieldData["value"] = localVault.Encrypt(value, itemEncKey, itemMacKey); // "true" or "false"

            dataFieldData["Name"] = localVault.Encrypt(name, itemEncKey, itemMacKey);
            dataFieldData["Type"] = 2;
            dataFieldData["Value"] = localVault.Encrypt(value, itemEncKey, itemMacKey);
        } else if (field == CustomFieldType::Linked) {
            addFieldData["linkedId"] = std::stoi(value);
            addFieldData["name"] = localVault.Encrypt(name, itemEncKey, itemMacKey);
            addFieldData["type"] = 3;
            addFieldData["value"] = nullptr;

            dataFieldData["Name"] = localVault.Encrypt(name, itemEncKey, itemMacKey);
            dataFieldData["Type"] = 3;
            dataFieldData["LinkedId"] = std::stoi(value);
        }

        fieldData["Fields"].push_back(dataFieldData);
        data["fields"].push_back(addFieldData);

        OPENSSL_cleanse(name.data(), name.size());
        name.clear();
        OPENSSL_cleanse(value.data(), value.size());
        value.clear();

        return *this;
    }

    SSHKeyItem& SSHKeyItem::RemoveField(std::string& name) {
        if (!init) return *this;
        if (!data.contains("fields") || !fieldData.contains("Fields")) return *this;
        if (fieldData["Fields"].is_null() || data["fields"].is_null()) {
            fieldData["Fields"] = nlohmann::json::object();
        }
        auto& fields = data["fields"];
        for (auto it = fields.begin(); it != fields.end(); ++it) {
            std::string decName = localVault.Decrypt((*it)["name"], itemEncKey, itemMacKey);
            if (decName == name) {
                OPENSSL_cleanse(decName.data(), decName.size());
                decName.clear();
                fields.erase(it);
                break;
            }

            OPENSSL_cleanse(decName.data(), decName.size());
            decName.clear();
        }

        auto& fieldsField = fieldData["Fields"];
        for (auto it = fieldsField.begin(); it != fieldsField.end(); ++it) {
            std::string decName = localVault.Decrypt((*it)["Name"], itemEncKey, itemMacKey);
            if (decName == name) {
                OPENSSL_cleanse(decName.data(), decName.size());
                decName.clear();
                fieldsField.erase(it);
                break;
            }

            OPENSSL_cleanse(decName.data(), decName.size());
            decName.clear();
        }

        OPENSSL_cleanse(name.data(), name.size());
        name.clear();
        return *this;
    }

    SSHKeyItem& SSHKeyItem::SetFavorite(bool val) {
        if (!init) return *this;
        data["favorite"] = val;
        return *this;
    }

    SSHKeyItem& SSHKeyItem::SetReprompt(bool val) {
        if (!init) return *this;
        if (val) {
            data["reprompt"] = 1;
        } else {
            data["reprompt"] = 0;
        }
        return *this;
    }

    SSHKeyItem& SSHKeyItem::GetFavorite(bool& val) {
        if (!init) return *this;
        if (!data.contains("favorite")) return *this;
        if (!data["favorite"].is_boolean()) return *this;
        val = data["favorite"];
        return *this;
    }

    SSHKeyItem& SSHKeyItem::GetReprompt(bool& val) {
        if (!init) return *this;
        if (!data.contains("reprompt")) return *this;
        if (!data["reprompt"].is_number()) return *this;
        if (data["reprompt"].get<int>() == 1) {
            val = true;
        }
        if (data["reprompt"].get<int>() == 0) {
            val = false;
        }
        return *this;
    }

    void SSHKeyItem::Commit() {
        if (!init) return;
        OPENSSL_cleanse(itemEncKey.data(), itemEncKey.size());
        itemEncKey.clear();
        OPENSSL_cleanse(itemMacKey.data(), itemMacKey.size());
        itemMacKey.clear();

        data["revisionDate"] = getBitwardenTime();
        data["data"] = fieldData.dump();
        if (isBeingCreated) {
            auto hr = localVault.OnlineNewItem(data);
            if (!hr) {
                logger->warn("Failed to add New Item Online");
                data["createdOffline"] = true;
            }
            localVault.vaultData["ciphers"].push_back(data);
            localVault.storage.write("vault.json", localVault.vaultData.dump(2));
            return;
        }

        auto& ciphers = localVault.vaultData["ciphers"];
        auto it = std::find_if(ciphers.begin(), ciphers.end(), [&](const nlohmann::json& cipher) {
            return cipher["id"] == data["id"];
        });

        if (it != ciphers.end()) {
            *it = data;
        }

        auto hr = localVault.OnlineUpdateItem(data);
        localVault.storage.write("vault.json", localVault.vaultData.dump(2));
    }

    void SSHKeyItem::Delete() {
        if (!init) return;
        if (!isBeingCreated) {
            OPENSSL_cleanse(itemEncKey.data(), itemEncKey.size());
            itemEncKey.clear();
            OPENSSL_cleanse(itemMacKey.data(), itemMacKey.size());
            itemMacKey.clear();
            auto& ciphers = localVault.vaultData["ciphers"];
            auto it = std::find_if(ciphers.begin(), ciphers.end(), [&](const nlohmann::json& cipher) {
                if (!cipher.contains("id") || cipher["id"].is_null()) return false;
                return cipher["id"].get<std::string>() == data["id"].get<std::string>();
            });

            if (it != ciphers.end()) {
                ciphers.erase(it);
            }
            auto hr = localVault.OnlineDeleteItem(data["id"]);
            if (hr != NetworkState::Success) {
                logger->warn("Failed to Delete Online Item");
                localVault.vaultData["deletedCiphers"].push_back(data["id"]);
            } 
        }
        localVault.storage.write("vault.json", localVault.vaultData.dump(2));
    }

    void SSHKeyItem::Bin() {
        if (!init) return;
        OPENSSL_cleanse(itemEncKey.data(), itemEncKey.size());
        itemEncKey.clear();
        OPENSSL_cleanse(itemMacKey.data(), itemMacKey.size());
        itemMacKey.clear();

        data["revisionDate"] = getBitwardenTime();
        data["deletedDate"] = getBitwardenTime();
        data["data"] = fieldData.dump();
        if (isBeingCreated) {
            auto hr = localVault.OnlineNewItem(data);
            if (!hr) {
                logger->warn("Failed to add New Item Online");
                data["createdOffline"] = true;
            }
            localVault.vaultData["ciphers"].push_back(data);
            localVault.storage.write("vault.json", localVault.vaultData.dump(2));
            return;
        }

        auto& ciphers = localVault.vaultData["ciphers"];
        auto it = std::find_if(ciphers.begin(), ciphers.end(), [&](const nlohmann::json& cipher) {
            return cipher["id"] == data["id"];
        });

        if (it != ciphers.end()) {
            *it = data;
        }

        auto hr = localVault.OnlineSoftDeleteItem(data["id"]);
        localVault.storage.write("vault.json", localVault.vaultData.dump(2));
    }

    void SSHKeyItem::UnBin() {
        if (!init) return;
        OPENSSL_cleanse(itemEncKey.data(), itemEncKey.size());
        itemEncKey.clear();
        OPENSSL_cleanse(itemMacKey.data(), itemMacKey.size());
        itemMacKey.clear();

        data["revisionDate"] = getBitwardenTime();
        data["deletedDate"] = nullptr;
        data["data"] = (std::string)fieldData.dump();
        if (isBeingCreated) {
            auto hr = localVault.OnlineNewItem(data);
            if (!hr) {
                logger->warn("Failed to add New Item Online");
                data["createdOffline"] = true;
            }
            localVault.vaultData["ciphers"].push_back(data);
            localVault.storage.write("vault.json", localVault.vaultData.dump(2));
            return;
        }

        auto& ciphers = localVault.vaultData["ciphers"];
        auto it = std::find_if(ciphers.begin(), ciphers.end(), [&](const nlohmann::json& cipher) {
            return cipher["id"] == data["id"];
        });

        if (it != ciphers.end()) {
            *it = data;
        }

        auto hr = localVault.OnlineRestoreItem(data["id"]);
        localVault.storage.write("vault.json", localVault.vaultData.dump(2));
    }

    void SSHKeyItem::Close() {
        if (!init) return;
        OPENSSL_cleanse(itemEncKey.data(), itemEncKey.size());
        itemEncKey.clear();
        OPENSSL_cleanse(itemMacKey.data(), itemMacKey.size());
        itemMacKey.clear();

        localVault.storage.write("vault.json", localVault.vaultData.dump(2));
    }

    SSHKeyItem& SSHKeyItem::GetName(std::string& name) {
        if (!init) return *this;
        if (!data.contains("name")) return *this;
        if (!data["name"].is_string()) return *this;
        name = localVault.Decrypt(data["name"], itemEncKey, itemMacKey);
        return *this;
    }

    SSHKeyItem& SSHKeyItem::GetFingerprint(std::string& fingerprint) {
        if (!init) return *this;
        if (!data["sshKey"].is_object()) return *this;
        if (!data["sshKey"].contains("keyFingerprint")) return *this;
        if (!data["sshKey"]["keyFingerprint"].is_string()) return *this;
        fingerprint = localVault.Decrypt(data["sshKey"]["keyFingerprint"], itemEncKey, itemMacKey);
        return *this;
    }

    SSHKeyItem& SSHKeyItem::GetPrivateKey(std::string& privateKey) {
        if (!init) return *this;
        if (!data["sshKey"].is_object()) return *this;
        if (!data["sshKey"].contains("privateKey")) return *this;
        if (!data["sshKey"]["privateKey"].is_string()) return *this;
        privateKey = localVault.Decrypt(data["sshKey"]["privateKey"], itemEncKey, itemMacKey);
        return *this;
    }

    SSHKeyItem& SSHKeyItem::GetPublicKey(std::string& publicKey) {
        if (!init) return *this;
        if (!data["sshKey"].is_object()) return *this;
        if (!data["sshKey"].contains("publicKey")) return *this;
        if (!data["sshKey"]["publicKey"].is_string()) return *this;
        publicKey = localVault.Decrypt(data["sshKey"]["publicKey"], itemEncKey, itemMacKey);
        return *this;
    }
    
    SSHKeyItem& SSHKeyItem::GetNotes(std::string& notes) {
        if (!init) return *this;
        if (!data.contains("notes")) return *this;
        if (!data["notes"].is_string()) return *this;
        notes = localVault.Decrypt(data["notes"], itemEncKey, itemMacKey);
        return *this;
    }

    SSHKeyItem& SSHKeyItem::GetFolder(std::string& folder) {
        if (!init) return *this;
        if (!data.contains("folderId")) return *this;
        if (!data["folderId"].is_string()) return *this;
        folder = data["folderId"].is_null() ? "" : data["folderId"].get<std::string>();
        return *this;
    }

    SSHKeyItem& SSHKeyItem::GetFields(std::vector<std::tuple<CustomFieldType, std::string, std::string>>& fields) {
        if (!init) return *this;
        if (!data.contains("fields")) return *this;
        if (!data["fields"].is_array()) return *this;
        fields.clear();
        for (auto& f : data["fields"]) {
            CustomFieldType type = static_cast<CustomFieldType>(f["type"].get<int>());
            std::string value;
            if (type == CustomFieldType::Linked) {
                value = f["linkedId"].is_null() ? "" : std::to_string(f["linkedId"].get<int>());
            } else {
                value = f["value"].is_null() ? "" : localVault.Decrypt(f["value"], itemEncKey, itemMacKey);
            }
            std::string name = localVault.Decrypt(f["name"], itemEncKey, itemMacKey);
            fields.emplace_back(type, std::move(name), std::move(value));
        }
        return *this;
    }

    SSHKeyItem& SSHKeyItem::GetId(std::string& value) {
        value = data["id"];

        return *this;
    }

    SSHKeyItem& SSHKeyItem::Duplicate(std::string& id) {
        auto keys = localVault.generateEncMacKeys();
        auto newitemEncKey = keys.first;
        auto newitemMacKey = keys.second;

        /*
         * SECRET DATA
        */
        std::string oldName;
        std::string oldFingerprint;
        std::string oldPrivKey;
        std::string oldPubKey;
        std::string oldNotes;
        std::vector<std::tuple<CustomFieldType, std::string, std::string>> oldFields;

        bool oldFavorite = false;
        int oldReprompt = 0;

        if (data.contains("name") && data["name"].is_string()) {
            oldName = localVault.Decrypt(data["name"], itemEncKey, itemMacKey);
        }

        if (data.contains("sshKey") && data["sshKey"].is_object()) {
            if (data["sshKey"].contains("keyFingerprint") && data["sshKey"]["keyFingerprint"].is_string()) {
                oldFingerprint = localVault.Decrypt(data["sshKey"]["keyFingerprint"], itemEncKey, itemMacKey);
            }
            if (data["sshKey"].contains("privateKey") && data["sshKey"]["privateKey"].is_string()) {
                oldPrivKey = localVault.Decrypt(data["sshKey"]["privateKey"], itemEncKey, itemMacKey);
            }
            if (data["sshKey"].contains("publicKey") && data["sshKey"]["publicKey"].is_string()) {
                oldPubKey = localVault.Decrypt(data["sshKey"]["publicKey"], itemEncKey, itemMacKey);
            }
        }

        if (data.contains("notes") && data["notes"].is_string()) {
            oldNotes = localVault.Decrypt(data["notes"], itemEncKey, itemMacKey);
        }

        if (data.contains("fields") && data["fields"].is_array()) {
            for (auto& field : data["fields"]) {
                CustomFieldType type = static_cast<CustomFieldType>(field["type"].get<int>());
                std::string fname = localVault.Decrypt(field["name"], itemEncKey, itemMacKey);
                std::string fval;
                if (type == CustomFieldType::Linked) {
                    fval = field["linkedId"].is_null() ? "" : std::to_string(field["linkedId"].get<int>());
                } else {
                    fval = field["value"].is_null() ? "" : localVault.Decrypt(field["value"], itemEncKey, itemMacKey);
                }
                oldFields.emplace_back(type, std::move(fname), std::move(fval));
            }
        }

        if (data.contains("favorite") && data["favorite"].is_boolean()) {
            oldFavorite = data["favorite"];
        }

        if (data.contains("reprompt") && data["reprompt"].is_number()) {
            oldReprompt = data["reprompt"];
        }

        nlohmann::json newdata;
        nlohmann::json newfieldData;

        newdata["archivedDate"] = nullptr;
        newdata["attachments"] = nullptr;
        newdata["card"] = nullptr;
        newdata["collectionIds"] = nlohmann::json::array();
        newdata["creationDate"] = getBitwardenTime();
        newdata["data"] = "";
        newdata["deletedDate"] = nullptr;
        newdata["edit"] = true;
        newdata["favorite"] = oldFavorite;
        newdata["fields"] = nlohmann::json::array();
        newdata["folderId"] = data["folderId"];
        newdata["id"] = uniqueGuid();
        newdata["identity"] = nullptr;
        std::vector<uint8_t> mainKey(newitemEncKey.begin(), newitemEncKey.end());
        mainKey.insert(mainKey.end(), newitemMacKey.begin(), newitemMacKey.end());
        newdata["key"] = localVault.InternalEncrypt(mainKey, localVault.encKey, localVault.macKey);
        OPENSSL_cleanse(mainKey.data(), mainKey.size());
        newdata["login"] = nullptr;
        newdata["name"] = localVault.Encrypt(oldName, newitemEncKey, newitemMacKey);
        newdata["notes"] = localVault.Encrypt(oldNotes, newitemEncKey, newitemMacKey);
        newdata["object"] = "cipherDetails";
        newdata["organizationId"] = nullptr;
        newdata["organizationUseTotp"] = false;
        newdata["passwordHistory"] = nullptr;
        newdata["permissions"] = nlohmann::json::object();
        newdata["permissions"]["delete"] = true;
        newdata["permissions"]["restore"] = true;
        newdata["reprompt"] = oldReprompt;
        newdata["revisionDate"] = nullptr;
        newdata["secureNote"] = nullptr;
        newdata["sshKey"] = nlohmann::json::object();
        newdata["sshKey"]["keyFingerprint"] = localVault.Encrypt(oldFingerprint, newitemEncKey, newitemMacKey);
        newdata["sshKey"]["privateKey"] = localVault.Encrypt(oldPrivKey, newitemEncKey, newitemMacKey);
        newdata["sshKey"]["publicKey"] = localVault.Encrypt(oldPubKey, newitemEncKey, newitemMacKey);
        newdata["type"] = 5;
        newdata["viewPassword"] = true;

        newfieldData["PrivateKey"] = localVault.Encrypt(oldPrivKey, newitemEncKey, newitemMacKey);
        newfieldData["PublicKey"] = localVault.Encrypt(oldPubKey, newitemEncKey, newitemMacKey);
        newfieldData["KeyFingerprint"] = localVault.Encrypt(oldFingerprint, newitemEncKey, newitemMacKey);
        newfieldData["Name"] = localVault.Encrypt(oldName, newitemEncKey, newitemMacKey);
        newfieldData["Notes"] = localVault.Encrypt(oldNotes, newitemEncKey, newitemMacKey);
        newfieldData["Fields"] = nlohmann::json::array();

        for (auto& [type, name, value] : oldFields) {
            nlohmann::json addFieldData;
            nlohmann::json dataFieldData;
            if (type == CustomFieldType::Text) {
                addFieldData["linkedId"] = nullptr;
                addFieldData["name"] = localVault.Encrypt(name, newitemEncKey, newitemMacKey);
                addFieldData["type"] = 0;
                addFieldData["value"] = localVault.Encrypt(value, newitemEncKey, newitemMacKey);

                dataFieldData["Name"] = localVault.Encrypt(name, newitemEncKey, newitemMacKey);
                dataFieldData["Type"] = 0;
                dataFieldData["Value"] = localVault.Encrypt(value, newitemEncKey, newitemMacKey);
            } else if (type == CustomFieldType::Hidden) {
                addFieldData["linkedId"] = nullptr;
                addFieldData["name"] = localVault.Encrypt(name, newitemEncKey, newitemMacKey);
                addFieldData["type"] = 1;
                addFieldData["value"] = localVault.Encrypt(value, newitemEncKey, newitemMacKey);

                dataFieldData["Name"] = localVault.Encrypt(name, newitemEncKey, newitemMacKey);
                dataFieldData["Type"] = 1;
                dataFieldData["Value"] = localVault.Encrypt(value, newitemEncKey, newitemMacKey);
            } else if (type == CustomFieldType::Checkbox) {
                addFieldData["linkedId"] = nullptr;
                addFieldData["name"] = localVault.Encrypt(name, newitemEncKey, newitemMacKey);
                addFieldData["type"] = 2;
                addFieldData["value"] = localVault.Encrypt(value, newitemEncKey, newitemMacKey); // "true" or "false"

                dataFieldData["Name"] = localVault.Encrypt(name, newitemEncKey, newitemMacKey);
                dataFieldData["Type"] = 2;
                dataFieldData["Value"] = localVault.Encrypt(value, newitemEncKey, newitemMacKey);
            } else if (type == CustomFieldType::Linked) {
                addFieldData["linkedId"] = std::stoi(value);
                addFieldData["name"] = localVault.Encrypt(name, newitemEncKey, newitemMacKey);
                addFieldData["type"] = 3;
                addFieldData["value"] = nullptr;

                dataFieldData["Name"] = localVault.Encrypt(name, newitemEncKey, newitemMacKey);
                dataFieldData["Type"] = 3;
                dataFieldData["LinkedId"] = std::stoi(value);
            }

            newfieldData["Fields"].push_back(dataFieldData);
            newdata["fields"].push_back(addFieldData);

            OPENSSL_cleanse(name.data(), name.size());
            name.clear();
            OPENSSL_cleanse(value.data(), value.size());
            value.clear();
        }

        OPENSSL_cleanse(oldName.data(), oldName.size());
        oldName.clear();
        OPENSSL_cleanse(oldFingerprint.data(), oldFingerprint.size());
        oldFingerprint.clear();
        OPENSSL_cleanse(oldPrivKey.data(), oldPrivKey.size());
        oldPrivKey.clear();
        OPENSSL_cleanse(oldPubKey.data(), oldPubKey.size());
        oldPubKey.clear();
        OPENSSL_cleanse(oldNotes.data(), oldNotes.size());
        oldNotes.clear();
        OPENSSL_cleanse(newitemEncKey.data(), newitemEncKey.size());
        newitemEncKey.clear();
        OPENSSL_cleanse(newitemMacKey.data(), newitemMacKey.size());
        newitemMacKey.clear();

        oldFavorite = false;
        oldReprompt = 0;

        newdata["revisionDate"] = getBitwardenTime();
        newdata["data"] = (std::string)newfieldData.dump();
        auto hr = localVault.OnlineNewItem(newdata);
        if (!hr) {
            logger->warn("Failed to add New Item Online");
            newdata["createdOffline"] = true;
        }
        localVault.vaultData["ciphers"].push_back(newdata);
        localVault.storage.write("vault.json", localVault.vaultData.dump(2));

        id = newdata["id"];

        return *this;
    }

    SSHKeyItem& SSHKeyItem::GetAttachmentIDs(std::vector<std::string>& ids) {
        if (!init) return *this;
        if (!data.contains("attachments")) return *this;
        if (!data["attachments"].is_array()) return *this;

        for (auto& attach : data["attachments"]) {
            if (!attach.is_object()) return *this;
            if (!attach["id"].is_string()) return *this;
            ids.push_back(attach["id"]);
        }
        return *this;
    }

    SSHKeyItem& SSHKeyItem::GetAttachmentName(std::string id, std::string& name) {
        if (!init) return *this;
        if (!data.contains("attachments")) return *this;
        if (!data["attachments"].is_array()) return *this;

        for (auto& attach : data["attachments"]) {
            if (!attach.is_object()) return *this;
            if (!attach.contains("id")) return *this;
            if (!attach["id"].is_string()) return *this;
            if (!attach.contains("fileName")) return *this;
            if (!attach["fileName"].is_string()) return *this;
            if (attach["id"] != id) continue;

            name = localVault.Decrypt(attach["fileName"], itemEncKey, itemMacKey);
            break;
        }
        return *this;
    }

    SSHKeyItem& SSHKeyItem::GetAttachment(std::string id, std::string& content) {
        if (!init) return *this;
        if (!data.contains("attachments")) return *this;
        if (!data["attachments"].is_array()) return *this;

        for (auto& attach : data["attachments"]) {
            if (!attach.is_object()) return *this;
            if (!attach["id"].is_string()) return *this;
            if (attach["id"] != id) continue;

            auto attachData = localVault.OnlineDownloadAttachment(data["id"].get<std::string>(), id);
            if (!attachData) return *this;
            content = attachData.value();
            OPENSSL_cleanse(attachData->data(), attachData->size());
            break;
        }
        return *this;
    }

    SSHKeyItem& SSHKeyItem::RemoveAttachment(std::string id) {
        if (!init) return *this;
        if (!data.contains("attachments")) return *this;
        if (!data["attachments"].is_array()) return *this;

        for (auto& attach : data["attachments"]) {
            if (!attach.is_object()) return *this;
            if (!attach["id"].is_string()) return *this;
            if (attach["id"] != id) continue;

            auto attachData = localVault.OnlineRemoveAttachment(data["id"].get<std::string>(), id);
            if (attachData != NetworkState::Success) return *this;
            auto& attachments = data["attachments"];
            attachments.erase(std::remove_if(attachments.begin(), attachments.end(),
                [&id](const nlohmann::json& a) {
                    return a.is_object() && a.contains("id") && a["id"] == id;
                }), attachments.end());
            break;
        }
        return *this;
    }

    SSHKeyItem& SSHKeyItem::AddAttachment(std::string& name, std::string& content, std::function<void(float)> onProgress) {
        if (!init) return *this;
        if (!data.contains("attachments")) return *this;
        if (!data["attachments"].is_array()) return *this;

        auto attachData = localVault.OnlineAddAttachment(data["id"].get<std::string>(), content, name);
        return *this;
    }
}