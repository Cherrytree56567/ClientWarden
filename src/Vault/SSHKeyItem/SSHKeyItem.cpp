#include "SSHKeyItem.h"

namespace ClientWarden {
    SSHKeyItem::SSHKeyItem(Vault& vault, std::string uuid) : GenericItem(vault, uuid) {
        if (!l_logger) {
            l_logger = spdlog::stdout_color_mt("ClientWarden::Vault::SSHKeyItem");
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

    SSHKeyItem::SSHKeyItem(Vault& vault) : GenericItem(vault) {
        if (!l_logger) {
            l_logger = spdlog::stdout_color_mt("ClientWarden::Vault::SSHKeyItem");
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

    SSHKeyItem* SSHKeyItem::SetName(std::string& name) {
        return static_cast<SSHKeyItem*>(this->GenericItem::SetName(name));
    }

    SSHKeyItem* SSHKeyItem::SetFingerprint(std::string& fingerprint) {
        if (!init) return this;
        if (!data.contains("sshKey") || !data["sshKey"].is_object()) return this;
        fieldData["KeyFingerprint"] = localVault.Encrypt(fingerprint, itemEncKey, itemMacKey);
        data["sshKey"]["keyFingerprint"] = localVault.Encrypt(fingerprint, itemEncKey, itemMacKey);
        OPENSSL_cleanse(fingerprint.data(), fingerprint.size());
        fingerprint.clear();
        return this;
    }

    SSHKeyItem* SSHKeyItem::SetPrivateKey(std::string& privateKey) {
        if (!init) return this;
        if (!data.contains("sshKey") || !data["sshKey"].is_object()) return this;
        fieldData["PrivateKey"] = localVault.Encrypt(privateKey, itemEncKey, itemMacKey);
        data["sshKey"]["privateKey"] = localVault.Encrypt(privateKey, itemEncKey, itemMacKey);
        OPENSSL_cleanse(privateKey.data(), privateKey.size());
        privateKey.clear();
        return this;
    }

    SSHKeyItem* SSHKeyItem::SetPublicKey(std::string& publicKey) {
        if (!init) return this;
        if (!data.contains("sshKey") || !data["sshKey"].is_object()) return this;
        fieldData["PublicKey"] = localVault.Encrypt(publicKey, itemEncKey, itemMacKey);
        data["sshKey"]["publicKey"] = localVault.Encrypt(publicKey, itemEncKey, itemMacKey);
        OPENSSL_cleanse(publicKey.data(), publicKey.size());
        publicKey.clear();
        return this;
    }

    SSHKeyItem* SSHKeyItem::SetNotes(std::string& notes) {
        return static_cast<SSHKeyItem*>(this->GenericItem::SetNotes(notes));
    }

    SSHKeyItem* SSHKeyItem::SetFolder(std::string folderUUID) {
        return static_cast<SSHKeyItem*>(this->GenericItem::SetFolder(folderUUID));
    }

    SSHKeyItem* SSHKeyItem::RemoveFolder() {
        return static_cast<SSHKeyItem*>(this->GenericItem::RemoveFolder());
    }

    SSHKeyItem* SSHKeyItem::AddField(CustomFieldType field, std::string& name, std::string& value) {
        return static_cast<SSHKeyItem*>(this->GenericItem::AddField(field, name, value));
    }

    SSHKeyItem* SSHKeyItem::RemoveField(std::string& name) {
        return static_cast<SSHKeyItem*>(this->GenericItem::RemoveField(name));
    }

    SSHKeyItem* SSHKeyItem::SetFavorite(bool val) {
        return static_cast<SSHKeyItem*>(this->GenericItem::SetFavorite(val));
    }

    SSHKeyItem* SSHKeyItem::SetReprompt(bool val) {
        return static_cast<SSHKeyItem*>(this->GenericItem::SetReprompt(val));
    }

    SSHKeyItem* SSHKeyItem::GetFavorite(bool& val) {
        return static_cast<SSHKeyItem*>(this->GenericItem::GetFavorite(val));
    }

    SSHKeyItem* SSHKeyItem::GetReprompt(bool& val) {
        return static_cast<SSHKeyItem*>(this->GenericItem::GetReprompt(val));
    }

    SSHKeyItem* SSHKeyItem::GetName(std::string& name) {
        return static_cast<SSHKeyItem*>(this->GenericItem::GetName(name));
    }

    SSHKeyItem* SSHKeyItem::GetFingerprint(std::string& fingerprint) {
        if (!init) return this;
        if (!data["sshKey"].is_object()) return this;
        if (!data["sshKey"].contains("keyFingerprint")) return this;
        if (!data["sshKey"]["keyFingerprint"].is_string()) return this;
        fingerprint = localVault.Decrypt(data["sshKey"]["keyFingerprint"], itemEncKey, itemMacKey);
        return this;
    }

    SSHKeyItem* SSHKeyItem::GetPrivateKey(std::string& privateKey) {
        if (!init) return this;
        if (!data["sshKey"].is_object()) return this;
        if (!data["sshKey"].contains("privateKey")) return this;
        if (!data["sshKey"]["privateKey"].is_string()) return this;
        privateKey = localVault.Decrypt(data["sshKey"]["privateKey"], itemEncKey, itemMacKey);
        return this;
    }

    SSHKeyItem* SSHKeyItem::GetPublicKey(std::string& publicKey) {
        if (!init) return this;
        if (!data["sshKey"].is_object()) return this;
        if (!data["sshKey"].contains("publicKey")) return this;
        if (!data["sshKey"]["publicKey"].is_string()) return this;
        publicKey = localVault.Decrypt(data["sshKey"]["publicKey"], itemEncKey, itemMacKey);
        return this;
    }
    
    SSHKeyItem* SSHKeyItem::GetNotes(std::string& notes) {
        return static_cast<SSHKeyItem*>(this->GenericItem::GetNotes(notes));
    }

    SSHKeyItem* SSHKeyItem::GetFolder(std::string& folder) {
        return static_cast<SSHKeyItem*>(this->GenericItem::GetFolder(folder));
    }

    SSHKeyItem* SSHKeyItem::GetFields(std::vector<std::tuple<CustomFieldType, std::string, std::string>>& fields) {
        return static_cast<SSHKeyItem*>(this->GenericItem::GetFields(fields));
    }

    SSHKeyItem* SSHKeyItem::GetId(std::string& value) {
        return static_cast<SSHKeyItem*>(this->GenericItem::GetId(value));
    }

    SSHKeyItem* SSHKeyItem::Duplicate(std::string& id) {
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
            l_logger->warn("Failed to add New Item Online");
            newdata["createdOffline"] = true;
        } else {
            if (hr->contains("id") && (*hr)["id"].is_string()) {
                newdata["id"] = (*hr)["id"];
            }
        }
        localVault.vaultData["ciphers"].push_back(newdata);
        localVault.storage.write("vault.json", localVault.vaultData.dump(2));

        id = newdata["id"];

        return this;
    }

    SSHKeyItem* SSHKeyItem::GetAttachmentIDs(std::vector<std::string>& ids) {
        return static_cast<SSHKeyItem*>(this->GenericItem::GetAttachmentIDs(ids));
    }

    SSHKeyItem* SSHKeyItem::GetAttachmentName(std::string id, std::string& name) {
        return static_cast<SSHKeyItem*>(this->GenericItem::GetAttachmentName(id, name));
    }

    SSHKeyItem* SSHKeyItem::GetAttachment(std::string id, std::string& content, std::function<void(float)> onProgress) {
        return static_cast<SSHKeyItem*>(this->GenericItem::GetAttachment(id, content, onProgress));
    }

    SSHKeyItem* SSHKeyItem::RemoveAttachment(std::string id) {
        return static_cast<SSHKeyItem*>(this->GenericItem::RemoveAttachment(id));
    }

    SSHKeyItem* SSHKeyItem::AddAttachment(std::string& name, std::string& content, std::string& id, std::function<void(float)> onProgress) {
        return static_cast<SSHKeyItem*>(this->GenericItem::AddAttachment(name, content, id, onProgress));
    }

    SSHKeyItem* SSHKeyItem::GetType(CipherType& val) {
        val = CipherType::SSHKey;
        return this;
    }

    SSHKeyItem* SSHKeyItem::GetCreation(std::string& value) {
        return static_cast<SSHKeyItem*>(this->GenericItem::GetCreation(value));
    }

    SSHKeyItem* SSHKeyItem::GetModification(std::string& value) {
        return static_cast<SSHKeyItem*>(this->GenericItem::GetModification(value));
    }

    SSHKeyItem* SSHKeyItem::GetDeletion(std::string& value) {
        return static_cast<SSHKeyItem*>(this->GenericItem::GetDeletion(value));
    }
}