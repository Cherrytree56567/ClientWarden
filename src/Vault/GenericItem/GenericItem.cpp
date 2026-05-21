#include "GenericItem.h"

namespace ClientWarden::Vault {
    GenericItem::GenericItem(Vault& vault, std::string uuid) : localVault(vault), isBeingCreated(false) {
        if (!logger) {
            logger = spdlog::stdout_color_mt("ClientWarden::Vault::GenericItem");
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
            if (data["type"].get<int>() == 1) {
                init = true;
            }
        }
        if (!data.contains("login")) {
            init = false;
        }
    }

    GenericItem::~GenericItem() {
        /*
        * TODO: Destruct
        */
        OPENSSL_cleanse(itemEncKey.data(), itemEncKey.size());
        itemEncKey.clear();
        OPENSSL_cleanse(itemMacKey.data(), itemMacKey.size());
        itemMacKey.clear();
    }

    GenericItem& GenericItem::GetId(std::string& value) {
        value = data["id"];

        return *this;
    }

    GenericItem& GenericItem::SetName(std::string& name) {
        if (!init) return *this;
        fieldData["Name"] = localVault.Encrypt(name, itemEncKey, itemMacKey);
        data["name"] = localVault.Encrypt(name, itemEncKey, itemMacKey);
        OPENSSL_cleanse(name.data(), name.size());
        name.clear();
        return *this;
    }

    GenericItem& GenericItem::SetNotes(std::string& notes) {
        if (!init) return *this;
        fieldData["Notes"] = localVault.Encrypt(notes, itemEncKey, itemMacKey);
        data["notes"] = localVault.Encrypt(notes, itemEncKey, itemMacKey);
        OPENSSL_cleanse(notes.data(), notes.size());
        notes.clear();
        return *this;
    }

    GenericItem& GenericItem::SetFolder(std::string folderUUID) {
        if (!init) return *this;
        data["folderId"] = folderUUID;
        return *this;
    }

    GenericItem& GenericItem::RemoveFolder() {
        if (!init) return *this;
        data["folderId"] = nullptr;
        return *this;
    }

    GenericItem& GenericItem::AddField(CustomFieldType field, std::string& name, std::string& value) {
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

    GenericItem& GenericItem::RemoveField(std::string& name) {
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

    void GenericItem::Commit() {
        if (!init) return;
        OPENSSL_cleanse(itemEncKey.data(), itemEncKey.size());
        itemEncKey.clear();
        OPENSSL_cleanse(itemMacKey.data(), itemMacKey.size());
        itemMacKey.clear();

        data["revisionDate"] = getBitwardenTime();
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

        auto hr = localVault.OnlineUpdateItem(data);
        localVault.storage.write("vault.json", localVault.vaultData.dump(2));
    }

    void GenericItem::Delete() {
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

    void GenericItem::Close() {
        if (!init) return;
        OPENSSL_cleanse(itemEncKey.data(), itemEncKey.size());
        itemEncKey.clear();
        OPENSSL_cleanse(itemMacKey.data(), itemMacKey.size());
        itemMacKey.clear();

        localVault.storage.write("vault.json", localVault.vaultData.dump(2));
    }

    void GenericItem::Bin() {
        if (!init) return;
        OPENSSL_cleanse(itemEncKey.data(), itemEncKey.size());
        itemEncKey.clear();
        OPENSSL_cleanse(itemMacKey.data(), itemMacKey.size());
        itemMacKey.clear();

        data["revisionDate"] = getBitwardenTime();
        data["deletedDate"] = getBitwardenTime();
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

        auto hr = localVault.OnlineSoftDeleteItem(data["id"]);
        localVault.storage.write("vault.json", localVault.vaultData.dump(2));
    }

    void GenericItem::UnBin() {
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

    GenericItem& GenericItem::GetName(std::string& name) {
        if (!init) return *this;
        if (!data.contains("name")) return *this;
        if (!data["name"].is_string()) return *this;
        name = localVault.Decrypt(data["name"], itemEncKey, itemMacKey);
        return *this;
    }

    GenericItem& GenericItem::GetNotes(std::string& notes) {
        if (!init) return *this;
        if (!data.contains("notes")) return *this;
        if (!data["notes"].is_string()) return *this;
        notes = localVault.Decrypt(data["notes"], itemEncKey, itemMacKey);
        return *this;
    }

    GenericItem& GenericItem::GetFolder(std::string& folder) {
        if (!init) return *this;
        if (!data.contains("folderId")) return *this;
        if (!data["folderId"].is_string()) return *this;
        folder = data["folderId"].is_null() ? "" : data["folderId"].get<std::string>();
        return *this;
    }

    GenericItem& GenericItem::GetFields(std::vector<std::tuple<CustomFieldType, std::string, std::string>>& fields) {
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

    GenericItem& GenericItem::SetFavorite(bool val) {
        if (!init) return *this;
        data["favorite"] = val;
        return *this;
    }

    GenericItem& GenericItem::SetReprompt(bool val) {
        if (!init) return *this;
        if (val) {
            data["reprompt"] = 1;
        } else {
            data["reprompt"] = 0;
        }
        return *this;
    }

    GenericItem& GenericItem::GetFavorite(bool& val) {
        if (!init) return *this;
        if (!data.contains("favorite")) return *this;
        if (!data["favorite"].is_boolean()) return *this;
        val = data["favorite"];
        return *this;
    }

    GenericItem& GenericItem::GetReprompt(bool& val) {
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

    GenericItem& GenericItem::GetAttachmentIDs(std::vector<std::string>& ids) {
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

    GenericItem& GenericItem::GetAttachmentName(std::string id, std::string& name) {
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

    GenericItem& GenericItem::GetAttachment(std::string id, std::string& content) {
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

    GenericItem& GenericItem::RemoveAttachment(std::string id) {
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

    GenericItem& GenericItem::AddAttachment(std::string& name, std::string& content, std::function<void(float)> onProgress) {
        if (!init) return *this;
        if (!data.contains("attachments")) return *this;
        if (!data["attachments"].is_array()) return *this;

        auto attachData = localVault.OnlineAddAttachment(data["id"].get<std::string>(), content, name);
        return *this;
    }
}