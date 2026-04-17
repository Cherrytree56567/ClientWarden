#include "NoteItem.h"

namespace ClientWarden::Vault {
    NoteItem::NoteItem(Vault& vault, std::string uuid) : localVault(vault), isBeingCreated(false) {
        logger = spdlog::stdout_color_mt("ClientWarden::Vault::NoteItem");
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
            fieldData = nlohmann::json::parse(data["data"].get<std::string>());
        }
        if (data.contains("key")) {
            auto keys = localVault.getKeysFromCipher(data["key"]);
            itemEncKey = keys.first;
            itemMacKey = keys.second;
        } else {
            init = false;
        }
        init = false;
        if (data.contains("type")) {
            if (data["type"].get<int>() == 2) {
                init = true;
            }
        }
    }

    NoteItem::NoteItem(Vault& vault) : localVault(vault), isBeingCreated(true) {
        logger = spdlog::stdout_color_mt("ClientWarden::Vault::NoteItem");
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
        data["secureNote"] = nlohmann::json::object();
        data["secureNote"]["type"] = 0;
        data["sshKey"] = nullptr;
        data["type"] = 2;
        data["viewPassword"] = true;

        fieldData["Type"] = 0;
        fieldData["Name"] = localVault.Encrypt("", itemEncKey, itemMacKey);
        fieldData["Notes"] = nullptr;
        fieldData["Fields"] = nlohmann::json::array();

        init = true;
    }

    NoteItem::~NoteItem() {
        /*
        * TODO: Destruct
        */
        OPENSSL_cleanse(itemEncKey.data(), itemEncKey.size());
        itemEncKey.clear();
        OPENSSL_cleanse(itemMacKey.data(), itemMacKey.size());
        itemMacKey.clear();
    }

    NoteItem& NoteItem::SetName(std::string& name) {
        if (!init) return *this;
        fieldData["Name"] = localVault.Encrypt(name, itemEncKey, itemMacKey);
        data["name"] = localVault.Encrypt(name, itemEncKey, itemMacKey);
        OPENSSL_cleanse(name.data(), name.size());
        name.clear();
        return *this;
    }

    NoteItem& NoteItem::SetNotes(std::string& notes) {
        if (!init) return *this;
        fieldData["Notes"] = localVault.Encrypt(notes, itemEncKey, itemMacKey);
        data["notes"] = localVault.Encrypt(notes, itemEncKey, itemMacKey);
        OPENSSL_cleanse(notes.data(), notes.size());
        notes.clear();
        return *this;
    }

    NoteItem& NoteItem::SetFolder(std::string folderUUID) {
        if (!init) return *this;
        data["folderId"] = folderUUID;
        return *this;
    }

    NoteItem& NoteItem::RemoveFolder() {
        if (!init) return *this;
        data["folderId"] = nullptr;
        return *this;
    }

    NoteItem& NoteItem::AddField(CustomFieldType field, std::string& name, std::string& value) {
        if (!init) return *this;
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

    NoteItem& NoteItem::RemoveField(std::string& name) {
        if (!init) return *this;
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

    void NoteItem::Bin() {
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
                spdlog::warn("Failed to add New Item Online");
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

    void NoteItem::Commit() {
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
                spdlog::warn("Failed to add New Item Online");
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

    void NoteItem::Delete() {
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
                spdlog::warn("Failed to Delete Online Item");
                localVault.vaultData["deletedCiphers"].push_back(data["id"]);
            } 
        }
        localVault.storage.write("vault.json", localVault.vaultData.dump(2));
    }

    void NoteItem::Close() {
        if (!init) return;
        OPENSSL_cleanse(itemEncKey.data(), itemEncKey.size());
        itemEncKey.clear();
        OPENSSL_cleanse(itemMacKey.data(), itemMacKey.size());
        itemMacKey.clear();

        localVault.storage.write("vault.json", localVault.vaultData.dump(2));
    }

    NoteItem& NoteItem::GetName(std::string& name) {
        if (!init) return *this;
        if (!data.contains("name")) return *this;
        name = localVault.Decrypt(data["name"], itemEncKey, itemMacKey);
        return *this;
    }

    NoteItem& NoteItem::GetNotes(std::string& notes) {
        if (!init) return *this;
        if (!data.contains("notes")) return *this;
        notes = localVault.Decrypt(data["notes"], itemEncKey, itemMacKey);
        return *this;
    }

    NoteItem& NoteItem::GetFolder(std::string& folder) {
        if (!init) return *this;
        if (!data.contains("folderId")) return *this;
        folder = data["folderId"].is_null() ? "" : data["folderId"].get<std::string>();
        return *this;
    }

    NoteItem& NoteItem::GetFields(std::vector<std::tuple<CustomFieldType, std::string, std::string>>& fields) {
        if (!init) return *this;
        if (!data.contains("fields")) return *this;
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

    NoteItem& NoteItem::SetFavorite(bool val) {
        if (!init) return *this;
        data["favorite"] = val;
        return *this;
    }

    NoteItem& NoteItem::SetReprompt(bool val) {
        if (!init) return *this;
        if (val) {
            data["reprompt"] = 1;
        } else {
            data["reprompt"] = 0;
        }
        return *this;
    }

    NoteItem& NoteItem::GetFavorite(bool& val) {
        if (!init) return *this;
        if (!data.contains("favorite")) return *this;
        val = data["favorite"];
        return *this;
    }

    NoteItem& NoteItem::GetReprompt(bool& val) {
        if (!init) return *this;
        if (!data.contains("reprompt")) return *this;
        if (data["reprompt"].get<int>() == 1) {
            val = true;
        }
        if (data["reprompt"].get<int>() == 0) {
            val = false;
        }
        return *this;
    }
}