#include "SSHKeyItem.h"
#include "Vault.h"

namespace ClientWarden {
    SSHKeyItem::SSHKeyItem(Vault& vault, std::string uuid) : GenericItemImpl<SSHKeyItem>(vault, uuid) {
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

    SSHKeyItem::SSHKeyItem(Vault& vault) : GenericItemImpl<SSHKeyItem>(vault) {
        auto keys = localVault.crypto.generateEncMacKeys();
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
        Botan::secure_vector<uint8_t> mainKey(itemEncKey.begin(), itemEncKey.end());
        mainKey.insert(mainKey.end(), itemMacKey.begin(), itemMacKey.end());
        data["key"] = localVault.crypto.Encrypt(mainKey, *localVault.session.encKey, *localVault.session.macKey);
        Botan::secure_scrub_memory(mainKey.data(), mainKey.size());
        data["login"] = nullptr;
        data["name"] = localVault.crypto.Encrypt("", itemEncKey, itemMacKey);
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
        data["sshKey"]["keyFingerprint"] = localVault.crypto.Encrypt("", itemEncKey, itemMacKey);
        data["sshKey"]["privateKey"] = localVault.crypto.Encrypt("", itemEncKey, itemMacKey);
        data["sshKey"]["publicKey"] = localVault.crypto.Encrypt("", itemEncKey, itemMacKey);
        data["type"] = 5;
        data["viewPassword"] = true;

        fieldData["PrivateKey"] = localVault.crypto.Encrypt("", itemEncKey, itemMacKey);
        fieldData["PublicKey"] = localVault.crypto.Encrypt("", itemEncKey, itemMacKey);
        fieldData["KeyFingerprint"] = localVault.crypto.Encrypt("", itemEncKey, itemMacKey);
        fieldData["Name"] = localVault.crypto.Encrypt("", itemEncKey, itemMacKey);
        fieldData["Notes"] = nullptr;
        fieldData["Fields"] = nlohmann::json::array();

        init = true;
    }

    SSHKeyItem* SSHKeyItem::SetFingerprint(std::string& fingerprint) {
        if (!init) return this;
        if (!data.contains("sshKey") || !data["sshKey"].is_object()) return this;
        fieldData["KeyFingerprint"] = localVault.crypto.Encrypt(fingerprint, itemEncKey, itemMacKey);
        data["sshKey"]["keyFingerprint"] = localVault.crypto.Encrypt(fingerprint, itemEncKey, itemMacKey);
        OPENSSL_cleanse(fingerprint.data(), fingerprint.size());
        fingerprint.clear();
        return this;
    }

    SSHKeyItem* SSHKeyItem::SetPrivateKey(std::string& privateKey) {
        if (!init) return this;
        if (!data.contains("sshKey") || !data["sshKey"].is_object()) return this;
        fieldData["PrivateKey"] = localVault.crypto.Encrypt(privateKey, itemEncKey, itemMacKey);
        data["sshKey"]["privateKey"] = localVault.crypto.Encrypt(privateKey, itemEncKey, itemMacKey);
        OPENSSL_cleanse(privateKey.data(), privateKey.size());
        privateKey.clear();
        return this;
    }

    SSHKeyItem* SSHKeyItem::SetPublicKey(std::string& publicKey) {
        if (!init) return this;
        if (!data.contains("sshKey") || !data["sshKey"].is_object()) return this;
        fieldData["PublicKey"] = localVault.crypto.Encrypt(publicKey, itemEncKey, itemMacKey);
        data["sshKey"]["publicKey"] = localVault.crypto.Encrypt(publicKey, itemEncKey, itemMacKey);
        OPENSSL_cleanse(publicKey.data(), publicKey.size());
        publicKey.clear();
        return this;
    }

    SSHKeyItem* SSHKeyItem::GetFingerprint(std::string& fingerprint) {
        if (!init) return this;
        if (!data["sshKey"].is_object()) return this;
        if (!data["sshKey"].contains("keyFingerprint")) return this;
        if (!data["sshKey"]["keyFingerprint"].is_string()) return this;
        fingerprint = localVault.crypto.DecryptAsStr(data["sshKey"]["keyFingerprint"], itemEncKey, itemMacKey);
        return this;
    }

    SSHKeyItem* SSHKeyItem::GetPrivateKey(std::string& privateKey) {
        if (!init) return this;
        if (!data["sshKey"].is_object()) return this;
        if (!data["sshKey"].contains("privateKey")) return this;
        if (!data["sshKey"]["privateKey"].is_string()) return this;
        privateKey = localVault.crypto.DecryptAsStr(data["sshKey"]["privateKey"], itemEncKey, itemMacKey);
        return this;
    }

    SSHKeyItem* SSHKeyItem::GetPublicKey(std::string& publicKey) {
        if (!init) return this;
        if (!data["sshKey"].is_object()) return this;
        if (!data["sshKey"].contains("publicKey")) return this;
        if (!data["sshKey"]["publicKey"].is_string()) return this;
        publicKey = localVault.crypto.DecryptAsStr(data["sshKey"]["publicKey"], itemEncKey, itemMacKey);
        return this;
    }

    SSHKeyItem* SSHKeyItem::Duplicate(std::string& id) {
        auto keys = localVault.crypto.generateEncMacKeys();
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
            oldName = localVault.crypto.DecryptAsStr(data["name"], itemEncKey, itemMacKey);
        }

        if (data.contains("sshKey") && data["sshKey"].is_object()) {
            if (data["sshKey"].contains("keyFingerprint") && data["sshKey"]["keyFingerprint"].is_string()) {
                oldFingerprint = localVault.crypto.DecryptAsStr(data["sshKey"]["keyFingerprint"], itemEncKey, itemMacKey);
            }
            if (data["sshKey"].contains("privateKey") && data["sshKey"]["privateKey"].is_string()) {
                oldPrivKey = localVault.crypto.DecryptAsStr(data["sshKey"]["privateKey"], itemEncKey, itemMacKey);
            }
            if (data["sshKey"].contains("publicKey") && data["sshKey"]["publicKey"].is_string()) {
                oldPubKey = localVault.crypto.DecryptAsStr(data["sshKey"]["publicKey"], itemEncKey, itemMacKey);
            }
        }

        if (data.contains("notes") && data["notes"].is_string()) {
            oldNotes = localVault.crypto.DecryptAsStr(data["notes"], itemEncKey, itemMacKey);
        }

        if (data.contains("fields") && data["fields"].is_array()) {
            for (auto& field : data["fields"]) {
                CustomFieldType type = static_cast<CustomFieldType>(field["type"].get<int>());
                std::string fname = localVault.crypto.DecryptAsStr(field["name"], itemEncKey, itemMacKey);
                std::string fval;
                if (type == CustomFieldType::Linked) {
                    fval = field["linkedId"].is_null() ? "" : std::to_string(field["linkedId"].get<int>());
                } else {
                    fval = field["value"].is_null() ? "" : localVault.crypto.DecryptAsStr(field["value"], itemEncKey, itemMacKey);
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
        Botan::secure_vector<uint8_t> mainKey(newitemEncKey.begin(), newitemEncKey.end());
        mainKey.insert(mainKey.end(), newitemMacKey.begin(), newitemMacKey.end());
        newdata["key"] = localVault.crypto.Encrypt(mainKey, *localVault.session.encKey, *localVault.session.macKey);
        Botan::secure_scrub_memory(mainKey.data(), mainKey.size());
        newdata["login"] = nullptr;
        newdata["name"] = localVault.crypto.Encrypt(oldName, newitemEncKey, newitemMacKey);
        newdata["notes"] = localVault.crypto.Encrypt(oldNotes, newitemEncKey, newitemMacKey);
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
        newdata["sshKey"]["keyFingerprint"] = localVault.crypto.Encrypt(oldFingerprint, newitemEncKey, newitemMacKey);
        newdata["sshKey"]["privateKey"] = localVault.crypto.Encrypt(oldPrivKey, newitemEncKey, newitemMacKey);
        newdata["sshKey"]["publicKey"] = localVault.crypto.Encrypt(oldPubKey, newitemEncKey, newitemMacKey);
        newdata["type"] = 5;
        newdata["viewPassword"] = true;

        newfieldData["PrivateKey"] = localVault.crypto.Encrypt(oldPrivKey, newitemEncKey, newitemMacKey);
        newfieldData["PublicKey"] = localVault.crypto.Encrypt(oldPubKey, newitemEncKey, newitemMacKey);
        newfieldData["KeyFingerprint"] = localVault.crypto.Encrypt(oldFingerprint, newitemEncKey, newitemMacKey);
        newfieldData["Name"] = localVault.crypto.Encrypt(oldName, newitemEncKey, newitemMacKey);
        newfieldData["Notes"] = localVault.crypto.Encrypt(oldNotes, newitemEncKey, newitemMacKey);
        newfieldData["Fields"] = nlohmann::json::array();

        for (auto& [type, name, value] : oldFields) {
            nlohmann::json addFieldData;
            nlohmann::json dataFieldData;
            if (type == CustomFieldType::Text) {
                addFieldData["linkedId"] = nullptr;
                addFieldData["name"] = localVault.crypto.Encrypt(name, newitemEncKey, newitemMacKey);
                addFieldData["type"] = 0;
                addFieldData["value"] = localVault.crypto.Encrypt(value, newitemEncKey, newitemMacKey);

                dataFieldData["Name"] = localVault.crypto.Encrypt(name, newitemEncKey, newitemMacKey);
                dataFieldData["Type"] = 0;
                dataFieldData["Value"] = localVault.crypto.Encrypt(value, newitemEncKey, newitemMacKey);
            } else if (type == CustomFieldType::Hidden) {
                addFieldData["linkedId"] = nullptr;
                addFieldData["name"] = localVault.crypto.Encrypt(name, newitemEncKey, newitemMacKey);
                addFieldData["type"] = 1;
                addFieldData["value"] = localVault.crypto.Encrypt(value, newitemEncKey, newitemMacKey);

                dataFieldData["Name"] = localVault.crypto.Encrypt(name, newitemEncKey, newitemMacKey);
                dataFieldData["Type"] = 1;
                dataFieldData["Value"] = localVault.crypto.Encrypt(value, newitemEncKey, newitemMacKey);
            } else if (type == CustomFieldType::Checkbox) {
                addFieldData["linkedId"] = nullptr;
                addFieldData["name"] = localVault.crypto.Encrypt(name, newitemEncKey, newitemMacKey);
                addFieldData["type"] = 2;
                addFieldData["value"] = localVault.crypto.Encrypt(value, newitemEncKey, newitemMacKey); // "true" or "false"

                dataFieldData["Name"] = localVault.crypto.Encrypt(name, newitemEncKey, newitemMacKey);
                dataFieldData["Type"] = 2;
                dataFieldData["Value"] = localVault.crypto.Encrypt(value, newitemEncKey, newitemMacKey);
            } else if (type == CustomFieldType::Linked) {
                addFieldData["linkedId"] = std::stoi(value);
                addFieldData["name"] = localVault.crypto.Encrypt(name, newitemEncKey, newitemMacKey);
                addFieldData["type"] = 3;
                addFieldData["value"] = nullptr;

                dataFieldData["Name"] = localVault.crypto.Encrypt(name, newitemEncKey, newitemMacKey);
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
        std::optional<nlohmann::json> result = localVault.NewItem(newdata);
        if (!result.has_value()) {
            logger->warn("Failed to add New Item Online");
            newdata["createdOffline"] = true;
        } else {
            if (result.value().contains("id") && result.value()["id"].is_string()) {
                newdata["id"] = result.value()["id"];
            }
        }
        (*localVault.session.vaultData)["ciphers"].push_back(newdata);
        localVault.storage.write("vault.json", localVault.session.vaultData->dump(2));

        id = newdata["id"];

        return this;
    }

    SSHKeyItem* SSHKeyItem::GetType(CipherType& val) {
        val = CipherType::SSHKey;
        return this;
    }
}