#include "GenericItem.h"
#include "Vault.h"

namespace ClientWarden {
    GenericItem::GenericItem(Vault& vault, std::string uuid) : localVault(vault), isBeingCreated(false) {
        if (!localVault.session.vaultData->contains("ciphers") || (*localVault.session.vaultData)["ciphers"].is_null()) return;
        data["id"] = uuid;
        for (auto& cipher : (*localVault.session.vaultData)["ciphers"]) {
            if (!cipher.contains("id")) {
                continue;
            }
            if (cipher["id"].get<std::string>() == uuid) {
                data = cipher;
                break;
            }
        }
        std::string dataStr = data.dump();
        if (data.contains("data")) {
            if (data["data"].is_string()) {
                fieldData = nlohmann::json::parse(data["data"].get<std::string>());
            } else {
                fieldData = data["data"];
                if (fieldData.contains("fields")) {
                    fieldData["Fields"] = fieldData["fields"];
                    fieldData.erase("fields");
                    for (auto& fieldD : fieldData["Fields"]) {
                        if (fieldD.contains("name")) {
                            fieldD["Name"] = fieldD["name"];
                            fieldD.erase("name");
                        }
                        if (fieldD.contains("type")) {
                            fieldD["Type"] = fieldD["type"];
                            fieldD.erase("Type");
                        }
                        if (fieldD.contains("value")) {
                            fieldD["Value"] = fieldD["value"];
                            fieldD.erase("Value");
                        }
                    }
                }
            }
        }
        if (data.contains("key")) {
            if (data["key"].is_null()) {
                itemEncKey = *localVault.session.encKey;
                itemMacKey = *localVault.session.macKey;
            } else  {
                auto keys = localVault.crypto.getEncMacKey(data["key"]);
                itemEncKey = keys.first;
                itemMacKey = keys.second;
            }
        } else {
            init = false;
            return;
        }
        init = true;
    }

    GenericItem::GenericItem(Vault& vault) : localVault(vault), isBeingCreated(true) {
        
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

    void GenericItem::GetIdImpl(std::string& value) {
        value = data["id"];

        return;
    }

    void GenericItem::SetNameImpl(std::string& name) {
        if (!init) return;
        fieldData["Name"] = localVault.crypto.Encrypt(name, itemEncKey, itemMacKey);
        data["name"] = localVault.crypto.Encrypt(name, itemEncKey, itemMacKey);
        OPENSSL_cleanse(name.data(), name.size());
        name.clear();
        return;
    }

    void GenericItem::SetNotesImpl(std::string& notes) {
        if (!init) return;
        fieldData["Notes"] = localVault.crypto.Encrypt(notes, itemEncKey, itemMacKey);
        data["notes"] = localVault.crypto.Encrypt(notes, itemEncKey, itemMacKey);
        OPENSSL_cleanse(notes.data(), notes.size());
        notes.clear();
        return;
    }

    void GenericItem::SetFolderImpl(std::string folderUUID) {
        if (!init) return;
        if (folderUUID == "") {
            data["folderId"] = nullptr;
        } else {
            data["folderId"] = folderUUID;
        }
        return;
    }

    void GenericItem::RemoveFolderImpl() {
        if (!init) return;
        data["folderId"] = nullptr;
        return;
    }

    void GenericItem::AddFieldImpl(CustomFieldType field, std::string& name, std::string& value) {
        if (!init) return;
        if (!data.contains("fields") || !fieldData.contains("Fields")) return;
        if (fieldData["Fields"].is_null() || !data["fields"].is_array()) {
            fieldData["Fields"] = nlohmann::json::array();
        }
        nlohmann::json addFieldData;
        nlohmann::json dataFieldData;
        if (field == CustomFieldType::Text) {
            addFieldData["linkedId"] = nullptr;
            addFieldData["name"] = localVault.crypto.Encrypt(name, itemEncKey, itemMacKey);
            addFieldData["type"] = 0;
            addFieldData["value"] = localVault.crypto.Encrypt(value, itemEncKey, itemMacKey);

            dataFieldData["Name"] = localVault.crypto.Encrypt(name, itemEncKey, itemMacKey);
            dataFieldData["Type"] = 0;
            dataFieldData["Value"] = localVault.crypto.Encrypt(value, itemEncKey, itemMacKey);
        } else if (field == CustomFieldType::Hidden) {
            addFieldData["linkedId"] = nullptr;
            addFieldData["name"] = localVault.crypto.Encrypt(name, itemEncKey, itemMacKey);
            addFieldData["type"] = 1;
            addFieldData["value"] = localVault.crypto.Encrypt(value, itemEncKey, itemMacKey);

            dataFieldData["Name"] = localVault.crypto.Encrypt(name, itemEncKey, itemMacKey);
            dataFieldData["Type"] = 1;
            dataFieldData["Value"] = localVault.crypto.Encrypt(value, itemEncKey, itemMacKey);
        } else if (field == CustomFieldType::Checkbox) {
            addFieldData["linkedId"] = nullptr;
            addFieldData["name"] = localVault.crypto.Encrypt(name, itemEncKey, itemMacKey);
            addFieldData["type"] = 2;
            addFieldData["value"] = localVault.crypto.Encrypt(value, itemEncKey, itemMacKey); // "true" or "false"

            dataFieldData["Name"] = localVault.crypto.Encrypt(name, itemEncKey, itemMacKey);
            dataFieldData["Type"] = 2;
            dataFieldData["Value"] = localVault.crypto.Encrypt(value, itemEncKey, itemMacKey);
        } else if (field == CustomFieldType::Linked) {
            addFieldData["linkedId"] = std::stoi(value);
            addFieldData["name"] = localVault.crypto.Encrypt(name, itemEncKey, itemMacKey);
            addFieldData["type"] = 3;
            addFieldData["value"] = nullptr;

            dataFieldData["Name"] = localVault.crypto.Encrypt(name, itemEncKey, itemMacKey);
            dataFieldData["Type"] = 3;
            dataFieldData["LinkedId"] = std::stoi(value);
        }

        fieldData["Fields"].push_back(dataFieldData);
        data["fields"].push_back(addFieldData);

        OPENSSL_cleanse(name.data(), name.size());
        name.clear();
        OPENSSL_cleanse(value.data(), value.size());
        value.clear();

        return;
    }

    void GenericItem::RemoveFieldImpl(std::string& name) {
        if (!init) return;
        if (!data.contains("fields") || !fieldData.contains("Fields")) return;
        if (fieldData["Fields"].is_null() || !data["fields"].is_array()) {
            fieldData["Fields"] = nlohmann::json::array();
        }
        auto& fields = data["fields"];
        for (auto it = fields.begin(); it != fields.end(); ++it) {
            std::string decName = localVault.crypto.DecryptAsStr((*it)["name"], itemEncKey, itemMacKey);
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
            std::string decName = localVault.crypto.DecryptAsStr((*it)["Name"], itemEncKey, itemMacKey);
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
        return;
    }

    void GenericItem::ClearFieldsImpl() {
        if (!init) return;
        if (!data.contains("fields") || !fieldData.contains("Fields")) return;
        if (fieldData["Fields"].is_null() || !data["fields"].is_array()) {
            fieldData["Fields"] = nlohmann::json::array();
        }
        
        fieldData["Fields"] = nlohmann::json::array();
        data["fields"] = nlohmann::json::array();

        return;
    }

    void GenericItem::Commit() {
        if (!init) return;
        OPENSSL_cleanse(itemEncKey.data(), itemEncKey.size());
        itemEncKey.clear();
        OPENSSL_cleanse(itemMacKey.data(), itemMacKey.size());
        itemMacKey.clear();

        data["revisionDate"] = getBitwardenTime();
        data["data"] = (std::string)fieldData.dump();
        if (isBeingCreated || (data.contains("createdOffline") && data["createdOffline"] == true)) {
            std::optional<nlohmann::json> result = localVault.NewItem(data, true, data);
            if (result.has_value()) {
                if (result.value().contains("id") && result.value()["id"].is_string()) {
                    data["id"] = result.value()["id"];
                }
            }
            return;
        }

        auto& ciphers = (*localVault.session.vaultData)["ciphers"];
        auto it = std::find_if(ciphers.begin(), ciphers.end(), [&](const nlohmann::json& cipher) {
            return cipher["id"] == data["id"];
        });

        if (it != ciphers.end()) {
            *it = data;
        }

        /*
         * We don't need to check this, bc if it doesn't update 
         * then the local one with have a higher revision Date
        */
        bool result = localVault.UpdateItem(data);
        std::string dataStr = data.dump();
        localVault.storage.write("vault.json", localVault.session.vaultData->dump(2));
    }

    void GenericItem::Delete() {
        if (!init) return;
        if (!isBeingCreated) {
            OPENSSL_cleanse(itemEncKey.data(), itemEncKey.size());
            itemEncKey.clear();
            OPENSSL_cleanse(itemMacKey.data(), itemMacKey.size());
            itemMacKey.clear();
            auto& ciphers = (*localVault.session.vaultData)["ciphers"];
            auto it = std::find_if(ciphers.begin(), ciphers.end(), [&](const nlohmann::json& cipher) {
                if (!cipher.contains("id") || cipher["id"].is_null()) return false;
                return cipher["id"].get<std::string>() == data["id"].get<std::string>();
            });

            if (it != ciphers.end()) {
                ciphers.erase(it);
            }
            
            localVault.DeleteItem(data["id"], true, data);
        }
    }

    void GenericItem::Close() {
        if (!init) return;
        OPENSSL_cleanse(itemEncKey.data(), itemEncKey.size());
        itemEncKey.clear();
        OPENSSL_cleanse(itemMacKey.data(), itemMacKey.size());
        itemMacKey.clear();

        localVault.storage.write("vault.json", localVault.session.vaultData->dump(2));
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
            std::optional<nlohmann::json> result = localVault.NewItem(data, true, data);
            return;
        }

        auto& ciphers = (*localVault.session.vaultData)["ciphers"];
        auto it = std::find_if(ciphers.begin(), ciphers.end(), [&](const nlohmann::json& cipher) {
            return cipher["id"] == data["id"];
        });

        if (it != ciphers.end()) {
            *it = data;
        }

        bool result = localVault.SoftDeleteItem(data["id"]);
        localVault.storage.write("vault.json", localVault.session.vaultData->dump(2));
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
            std::optional<nlohmann::json> result = localVault.NewItem(data, true, data);
            return;
        }

        auto& ciphers = (*localVault.session.vaultData)["ciphers"];
        auto it = std::find_if(ciphers.begin(), ciphers.end(), [&](const nlohmann::json& cipher) {
            return cipher["id"] == data["id"];
        });

        if (it != ciphers.end()) {
            *it = data;
        }

        bool result = localVault.RestoreItem(data["id"]);
        localVault.storage.write("vault.json", localVault.session.vaultData->dump(2));
    }

    void GenericItem::GetNameImpl(std::string& name) {
        if (!init) return;
        if (!data.contains("name")) return;
        if (!data["name"].is_string()) return;
        name = localVault.crypto.DecryptAsStr(data["name"], itemEncKey, itemMacKey);
        return;
    }

    void GenericItem::GetNotesImpl(std::string& notes) {
        if (!init) return;
        if (!data.contains("notes")) return;
        if (!data["notes"].is_string()) return;
        notes = localVault.crypto.DecryptAsStr(data["notes"], itemEncKey, itemMacKey);
        return;
    }

    void GenericItem::GetFolderImpl(std::string& folder) {
        if (!init) return;
        if (!data.contains("folderId")) return;
        if (!data["folderId"].is_string()) return;
        folder = data["folderId"].is_null() ? "" : data["folderId"].get<std::string>();
        return;
    }

    void GenericItem::GetFieldsImpl(std::vector<std::tuple<CustomFieldType, std::string, std::string>>& fields) {
        if (!init) return;
        if (!data.contains("fields")) return;
        if (!data["fields"].is_array()) return;
        fields.clear();
        for (auto& f : data["fields"]) {
            CustomFieldType type = static_cast<CustomFieldType>(f["type"].get<int>());
            std::string value;
            if (type == CustomFieldType::Linked) {
                value = f["linkedId"].is_null() ? "" : std::to_string(f["linkedId"].get<int>());
            } else {
                value = f["value"].is_null() ? "" : localVault.crypto.DecryptAsStr(f["value"], itemEncKey, itemMacKey);
            }
            std::string name = localVault.crypto.DecryptAsStr(f["name"], itemEncKey, itemMacKey);
            fields.emplace_back(type, std::move(name), std::move(value));
        }
        return;
    }

    void GenericItem::SetFavoriteImpl(bool val) {
        if (!init) return;
        data["favorite"] = val;
        return;
    }

    void GenericItem::SetRepromptImpl(bool val) {
        if (!init) return;
        if (val) {
            data["reprompt"] = 1;
        } else {
            data["reprompt"] = 0;
        }
        return;
    }

    void GenericItem::GetFavoriteImpl(bool& val) {
        if (!init) return;
        if (!data.contains("favorite")) return;
        if (!data["favorite"].is_boolean()) return;
        val = data["favorite"];
        return;
    }

    void GenericItem::GetRepromptImpl(bool& val) {
        if (!init) return;
        if (!data.contains("reprompt")) return;
        if (!data["reprompt"].is_number()) return;
        if (data["reprompt"].get<int>() == 1) {
            val = true;
        }
        if (data["reprompt"].get<int>() == 0) {
            val = false;
        }
        return;
    }

    void GenericItem::GetAttachmentIDsImpl(std::vector<std::string>& ids) {
        if (!init) return;
        if (!data.contains("attachments")) return;
        if (!data["attachments"].is_array()) return;

        for (auto& attach : data["attachments"]) {
            if (!attach.is_object()) return;
            if (!attach["id"].is_string()) return;
            ids.push_back(attach["id"]);
        }
        return;
    }

    void GenericItem::GetAttachmentNameImpl(std::string id, std::string& name) {
        if (!init) return;
        if (!data.contains("attachments")) return;
        if (!data["attachments"].is_array()) return;

        for (auto& attach : data["attachments"]) {
            if (!attach.is_object()) return;
            if (!attach.contains("id")) return;
            if (!attach["id"].is_string()) return;
            if (!attach.contains("fileName")) return;
            if (!attach["fileName"].is_string()) return;
            if (attach["id"] != id) continue;

            name = localVault.crypto.DecryptAsStr(attach["fileName"], itemEncKey, itemMacKey);
            break;
        }
        return;
    }

    void GenericItem::GetAttachmentImpl(std::string id, std::filesystem::path filePath, std::function<void(float)> onProgress) {
        if (!init) return;
        if (!data.contains("attachments")) return;
        if (!data["attachments"].is_array()) return;

        for (auto& attach : data["attachments"]) {
            if (!attach.is_object()) return;
            if (!attach["id"].is_string()) return;
            if (attach["id"] != id) continue;

            bool result = localVault.DownloadAttachment(data["id"].get<std::string>(), id, filePath, itemEncKey, 
                itemMacKey, onProgress);
            if (!result) return;
            break;
        }
        return;
    }

    void GenericItem::RemoveAttachmentImpl(std::string id) {
        if (!init) return;
        if (!data.contains("attachments")) return;
        if (!data["attachments"].is_array()) return;

        for (auto& attach : data["attachments"]) {
            if (!attach.is_object()) return;
            if (!attach["id"].is_string()) return;
            if (attach["id"] != id) continue;

            bool result = localVault.RemoveAttachment(data["id"].get<std::string>(), id);
            if (!result) return;
            auto& attachments = data["attachments"];
            attachments.erase(std::remove_if(attachments.begin(), attachments.end(),
                [&id](const nlohmann::json& a) {
                    return a.is_object() && a.contains("id") && a["id"] == id;
                }), attachments.end());
            break;
        }
        return;
    }

    void GenericItem::AddAttachmentImpl(std::string& name, std::string& content, std::string& id, std::function<void(float)> onProgress) {
        if (!init) return;
        if (!data.contains("attachments")) return;
        if (!data["attachments"].is_array()) {
            data["attachments"] = nlohmann::json::array();
        }

        std::optional<nlohmann::json> result = localVault.AddAttachment(data["id"].get<std::string>(), content, name, onProgress);
        
        if (result.has_value()) {
            if (!result.value().contains("attachmentId") || !result.value().contains("cipherResponse")) {
                return;
            }
            if (!result.value()["cipherResponse"].contains("attachments")) {
                return;
            }

            auto attachmentField = result.value()["cipherResponse"]["attachments"];

            data["attachments"] = attachmentField;
            id = result.value()["attachmentId"];
        }
        return;
    }

    GenericItem* GenericItem::GetType(CipherType& val) {
        if (!init) return this;
        if (!data.contains("type")) return this;
        if (!data["type"].is_number()) return this;
        val = (CipherType)data["type"].get<int>();
        return this;
    }

    void GenericItem::GetCreationImpl(std::string& value) {
        if (!init) return;
        if (!data.contains("creationDate")) return;
        if (!data["creationDate"].is_string()) return;

        std::time_t time = BitwardenTime(data["creationDate"]);

        std::tm tmStruct{};
        #if defined(_WIN32)
            localtime_s(&tmStruct, &time);
        #else
            localtime_r(&time, &tmStruct);
        #endif

        std::ostringstream oss;
        oss << std::put_time(&tmStruct, "%Y-%m-%d %H:%M:%S");
        value = oss.str();
        return;
    }

    void GenericItem::GetModificationImpl(std::string& value) {
        if (!init) return;
        if (!data.contains("revisionDate")) return;
        if (!data["revisionDate"].is_string()) return;

        std::time_t time = BitwardenTime(data["revisionDate"]);

        std::tm tmStruct{};
        #if defined(_WIN32)
            localtime_s(&tmStruct, &time);
        #else
            localtime_r(&time, &tmStruct);
        #endif

        std::ostringstream oss;
        oss << std::put_time(&tmStruct, "%Y-%m-%d %H:%M:%S");
        value = oss.str();
        return;
    }

    void GenericItem::GetDeletionImpl(std::string& value) {
        if (!init) return;
        if (!data.contains("GetDeletion")) return;
        if (!data["GetDeletion"].is_string()) {
            value = "none";
            return;
        }

        std::time_t time = BitwardenTime(data["GetDeletion"]);

        std::tm tmStruct{};
        #if defined(_WIN32)
            localtime_s(&tmStruct, &time);
        #else
            localtime_r(&time, &tmStruct);
        #endif

        std::ostringstream oss;
        oss << std::put_time(&tmStruct, "%Y-%m-%d %H:%M:%S");
        value = oss.str();
        return;
    }

    GenericItem* GenericItem::SetName(std::string& name) {
        SetNameImpl(name);
        return this;
    }
        
    GenericItem* GenericItem::SetNotes(std::string& notes) {
        SetNotesImpl(notes);
        return this;
    }
        
    GenericItem* GenericItem::SetFolder(std::string folder) {
        SetFolderImpl(folder);
        return this;
    }
        
    GenericItem* GenericItem::RemoveFolder() {
        RemoveFolderImpl();
        return this;
    }
        
    GenericItem* GenericItem::AddField(CustomFieldType field, std::string& name, std::string& value) {
        AddFieldImpl(field, name, value);
        return this;
    }
        
    GenericItem* GenericItem::RemoveField(std::string& name) {
        RemoveFieldImpl(name);
        return this;
    }
        
    GenericItem* GenericItem::ClearFields() {
        ClearFieldsImpl();
        return this;
    }
        
    GenericItem* GenericItem::GetName(std::string& name) {
        GetNameImpl(name);
        return this;
    }
        
    GenericItem* GenericItem::GetNotes(std::string& notes) {
        GetNotesImpl(notes);
        return this;
    }
        
    GenericItem* GenericItem::GetFolder(std::string& folder) {
        GetFolderImpl(folder);
        return this;
    }
        
    GenericItem* GenericItem::GetFields(std::vector<std::tuple<CustomFieldType, std::string, std::string>>& value) {
        GetFieldsImpl(value);
        return this;
    }
        
    GenericItem* GenericItem::GetId(std::string& value) {
        GetIdImpl(value);
        return this;
    }
        
    GenericItem* GenericItem::GetCreation(std::string& value) {
        GetCreationImpl(value);
        return this;
    }
        
    GenericItem* GenericItem::GetModification(std::string& value) {
        GetModificationImpl(value);
        return this;
    }
        
    GenericItem* GenericItem::GetDeletion(std::string& value) {
        GetDeletionImpl(value);
        return this;
    }
        
    GenericItem* GenericItem::AddAttachment(std::string& name, std::string& content, std::string& id, std::function<void(float)> onProgress) {
        AddAttachmentImpl(name, content, id, onProgress);
        return this;
    }
        
    GenericItem* GenericItem::GetAttachmentIDs(std::vector<std::string>& ids) {
        GetAttachmentIDsImpl(ids);
        return this;
    }
        
    GenericItem* GenericItem::GetAttachmentName(std::string id, std::string& name) {
        GetAttachmentNameImpl(id, name);
        return this;
    }
        
    GenericItem* GenericItem::GetAttachment(std::string id, std::filesystem::path filePath, std::function<void(float)> onProgress) {
        GetAttachmentImpl(id, filePath, onProgress);
        return this;
    }
        
    GenericItem* GenericItem::RemoveAttachment(std::string id) {
        RemoveAttachmentImpl(id);
        return this;
    }
        
    GenericItem* GenericItem::SetFavorite(bool val) {
        SetFavoriteImpl(val);
        return this;
    }
        
    GenericItem* GenericItem::SetReprompt(bool val) {
        SetRepromptImpl(val);
        return this;
    }
        
    GenericItem* GenericItem::GetFavorite(bool& val) {
        GetFavoriteImpl(val);
        return this;
    }
        
    GenericItem* GenericItem::GetReprompt(bool& val) {
        GetRepromptImpl(val);
        return this;
    }
}