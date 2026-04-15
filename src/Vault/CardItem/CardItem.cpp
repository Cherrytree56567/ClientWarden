#include "CardItem.h"

namespace ClientWarden::Vault {
    CardItem::CardItem(Vault& vault, std::string uuid) : localVault(vault), isBeingCreated(false) {
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
            if (data["type"].get<int>() == 3) {
                init = true;
            }
        }
        if (!data.contains("card")) {
            init = false;
        }
    }

    CardItem::CardItem(Vault& vault) : localVault(vault), isBeingCreated(true) {
        auto keys = localVault.generateEncMacKeys();
        itemEncKey = keys.first;
        itemMacKey = keys.second;

        data["archivedDate"] = nullptr;
        data["attachments"] = nullptr;
        data["card"] = nlohmann::json::object();
        data["card"]["brand"] = nullptr;
        data["card"]["cardholderName"] = nullptr;
        data["card"]["code"] = nullptr;
        data["card"]["expMonth"] = nullptr;
        data["card"]["expYear"] = nullptr;
        data["card"]["number"] = nullptr;
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
        data["sshKey"] = nullptr;
        data["type"] = 3;
        data["viewPassword"] = true;

        fieldData["CardholderName"] = nullptr;
        fieldData["Brand"] = nullptr;
        fieldData["Number"] = nullptr;
        fieldData["ExpMonth"] = nullptr;
        fieldData["ExpYear"] = nullptr;
        fieldData["Code"] = nullptr;
        fieldData["Name"] = localVault.Encrypt("", itemEncKey, itemMacKey);
        fieldData["Notes"] = nullptr;
        fieldData["Fields"] = nlohmann::json::array();

        init = true;
    }

    CardItem::~CardItem() {
        /*
        * TODO: Destruct
        */
        OPENSSL_cleanse(itemEncKey.data(), itemEncKey.size());
        itemEncKey.clear();
        OPENSSL_cleanse(itemMacKey.data(), itemMacKey.size());
        itemMacKey.clear();
    }

    CardItem& CardItem::SetName(std::string& name) {
        if (!init) return *this;
        fieldData["Name"] = localVault.Encrypt(name, itemEncKey, itemMacKey);
        data["name"] = localVault.Encrypt(name, itemEncKey, itemMacKey);
        OPENSSL_cleanse(name.data(), name.size());
        name.clear();
        return *this;
    }

    CardItem& CardItem::SetBrand(std::string& brand) {
        if (!init) return *this;
        fieldData["Brand"] = localVault.Encrypt(brand, itemEncKey, itemMacKey);
        data["card"]["brand"] = localVault.Encrypt(brand, itemEncKey, itemMacKey);
        OPENSSL_cleanse(brand.data(), brand.size());
        brand.clear();
        return *this;
    }

    CardItem& CardItem::SetCardholderName(std::string& cardholderName) {
        if (!init) return *this;
        fieldData["CardholderName"] = localVault.Encrypt(cardholderName, itemEncKey, itemMacKey);
        data["card"]["cardholderName"] = localVault.Encrypt(cardholderName, itemEncKey, itemMacKey);
        OPENSSL_cleanse(cardholderName.data(), cardholderName.size());
        cardholderName.clear();
        return *this;
    }

    CardItem& CardItem::SetCode(std::string& code) {
        if (!init) return *this;
        fieldData["Code"] = localVault.Encrypt(code, itemEncKey, itemMacKey);
        data["card"]["code"] = localVault.Encrypt(code, itemEncKey, itemMacKey);
        OPENSSL_cleanse(code.data(), code.size());
        code.clear();
        return *this;
    }

    CardItem& CardItem::SetExpMonth(std::string& expMonth) {
        if (!init) return *this;
        fieldData["ExpMonth"] = localVault.Encrypt(expMonth, itemEncKey, itemMacKey);
        data["card"]["expMonth"] = localVault.Encrypt(expMonth, itemEncKey, itemMacKey);
        OPENSSL_cleanse(expMonth.data(), expMonth.size());
        expMonth.clear();
        return *this;
    }

    CardItem& CardItem::SetExpYear(std::string& expYear) {
        if (!init) return *this;
        fieldData["ExpYear"] = localVault.Encrypt(expYear, itemEncKey, itemMacKey);
        data["card"]["expYear"] = localVault.Encrypt(expYear, itemEncKey, itemMacKey);
        OPENSSL_cleanse(expYear.data(), expYear.size());
        expYear.clear();
        return *this;
    }

    CardItem& CardItem::SetNumber(std::string& number) {
        if (!init) return *this;
        fieldData["Number"] = localVault.Encrypt(number, itemEncKey, itemMacKey);
        data["card"]["number"] = localVault.Encrypt(number, itemEncKey, itemMacKey);
        OPENSSL_cleanse(number.data(), number.size());
        number.clear();
        return *this;
    }

    CardItem& CardItem::SetNotes(std::string& notes) {
        if (!init) return *this;
        fieldData["Notes"] = localVault.Encrypt(notes, itemEncKey, itemMacKey);
        data["notes"] = localVault.Encrypt(notes, itemEncKey, itemMacKey);
        OPENSSL_cleanse(notes.data(), notes.size());
        notes.clear();
        return *this;
    }

    CardItem& CardItem::SetFolder(std::string folderUUID) {
        if (!init) return *this;
        data["folderId"] = folderUUID;
        return *this;
    }

    CardItem& CardItem::RemoveFolder() {
        if (!init) return *this;
        data["folderId"] = nullptr;
        return *this;
    }

    CardItem& CardItem::AddField(CustomFieldType field, std::string& name, std::string& value) {
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

    CardItem& CardItem::RemoveField(std::string& name) {
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

    CardItem& CardItem::SetFavorite(bool val) {
        if (!init) return *this;
        data["favorite"] = val;
        return *this;
    }

    CardItem& CardItem::SetReprompt(bool val) {
        if (!init) return *this;
        if (val) {
            data["reprompt"] = 1;
        } else {
            data["reprompt"] = 0;
        }
        return *this;
    }

    CardItem& CardItem::GetFavorite(bool& val) {
        if (!init) return *this;
        if (!data.contains("favorite")) return *this;
        val = data["favorite"];
        return *this;
    }

    CardItem& CardItem::GetReprompt(bool& val) {
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

    void CardItem::Commit() {
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

    void CardItem::Delete() {
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

    void CardItem::Bin() {
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

    void CardItem::Close() {
        if (!init) return;
        OPENSSL_cleanse(itemEncKey.data(), itemEncKey.size());
        itemEncKey.clear();
        OPENSSL_cleanse(itemMacKey.data(), itemMacKey.size());
        itemMacKey.clear();

        localVault.storage.write("vault.json", localVault.vaultData.dump(2));
    }

    CardItem& CardItem::GetName(std::string& name) {
        if (!init) return *this;
        if (!data.contains("name")) return *this;
        name = localVault.Decrypt(data["name"], itemEncKey, itemMacKey);
        return *this;
    }

    CardItem& CardItem::GetBrand(std::string& brand) {
        if (!init) return *this;
        if (!data["card"].contains("brand")) return *this;
        brand = localVault.Decrypt(data["card"]["brand"], itemEncKey, itemMacKey);
        return *this;
    }

    CardItem& CardItem::GetCardholderName(std::string& cardholderName) {
        if (!init) return *this;
        if (!data["card"].contains("cardholderName")) return *this;
        cardholderName = localVault.Decrypt(data["card"]["cardholderName"], itemEncKey, itemMacKey);
        return *this;
    }

    CardItem& CardItem::GetCode(std::string& code) {
        if (!init) return *this;
        if (!data["card"].contains("code")) return *this;
        code = localVault.Decrypt(data["card"]["code"], itemEncKey, itemMacKey);
        return *this;
    }

    CardItem& CardItem::GetExpMonth(std::string& expMonth) {
        if (!init) return *this;
        if (!data["card"].contains("expMonth")) return *this;
        expMonth = localVault.Decrypt(data["card"]["expMonth"], itemEncKey, itemMacKey);
        return *this;
    }

    CardItem& CardItem::GetExpYear(std::string& expYear) {
        if (!init) return *this;
        if (!data["card"].contains("expYear")) return *this;
        expYear = localVault.Decrypt(data["card"]["expYear"], itemEncKey, itemMacKey);
        return *this;
    }

    CardItem& CardItem::GetNumber(std::string& number) {
        if (!init) return *this;
        if (!data["card"].contains("number")) return *this;
        number = localVault.Decrypt(data["card"]["number"], itemEncKey, itemMacKey);
        return *this;
    }

    CardItem& CardItem::GetNotes(std::string& notes) {
        if (!init) return *this;
        if (!data.contains("notes")) return *this;
        notes = localVault.Decrypt(data["notes"], itemEncKey, itemMacKey);
        return *this;
    }

    CardItem& CardItem::GetFolder(std::string& folder) {
        if (!init) return *this;
        if (!data.contains("folderId")) return *this;
        folder = data["folderId"].is_null() ? "" : data["folderId"].get<std::string>();
        return *this;
    }

    CardItem& CardItem::GetFields(std::vector<std::tuple<CustomFieldType, std::string, std::string>>& fields) {
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
}