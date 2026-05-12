#include "CardItem.h"

namespace ClientWarden::Vault {
    CardItem::CardItem(Vault& vault, std::string uuid) : localVault(vault), isBeingCreated(false) {
        if (!logger) {
            logger = spdlog::stdout_color_mt("ClientWarden::Vault::CardItem");
        }
        if (!localVault.vaultData.contains("ciphers") || localVault.vaultData["ciphers"].is_null()) return;
        data["id"] = uuid;
        for (auto& cipher : localVault.vaultData["ciphers"]) {
            if (!cipher.contains("id") || cipher["id"].is_null()) {
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
        if (data.contains("type") || data["type"].is_number()) {
            if (data["type"].get<int>() == 3) {
                init = true;
            }
        }
        if (!data.contains("card")) {
            init = false;
        }
    }

    CardItem::CardItem(Vault& vault) : localVault(vault), isBeingCreated(true) {
        if (!logger) {
            logger = spdlog::stdout_color_mt("ClientWarden::Vault::CardItem");
        }
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
        if (!data.contains("card") || !data["card"].is_object()) return *this;
        fieldData["Brand"] = localVault.Encrypt(brand, itemEncKey, itemMacKey);
        data["card"]["brand"] = localVault.Encrypt(brand, itemEncKey, itemMacKey);
        OPENSSL_cleanse(brand.data(), brand.size());
        brand.clear();
        return *this;
    }

    CardItem& CardItem::SetCardholderName(std::string& cardholderName) {
        if (!init) return *this;
        if (!data.contains("card") || !data["card"].is_object()) return *this;
        fieldData["CardholderName"] = localVault.Encrypt(cardholderName, itemEncKey, itemMacKey);
        data["card"]["cardholderName"] = localVault.Encrypt(cardholderName, itemEncKey, itemMacKey);
        OPENSSL_cleanse(cardholderName.data(), cardholderName.size());
        cardholderName.clear();
        return *this;
    }

    CardItem& CardItem::SetCode(std::string& code) {
        if (!init) return *this;
        if (!data.contains("card") || !data["card"].is_object()) return *this;
        fieldData["Code"] = localVault.Encrypt(code, itemEncKey, itemMacKey);
        data["card"]["code"] = localVault.Encrypt(code, itemEncKey, itemMacKey);
        OPENSSL_cleanse(code.data(), code.size());
        code.clear();
        return *this;
    }

    CardItem& CardItem::SetExpMonth(std::string& expMonth) {
        if (!init) return *this;
        if (!data.contains("card") || !data["card"].is_object()) return *this;
        fieldData["ExpMonth"] = localVault.Encrypt(expMonth, itemEncKey, itemMacKey);
        data["card"]["expMonth"] = localVault.Encrypt(expMonth, itemEncKey, itemMacKey);
        OPENSSL_cleanse(expMonth.data(), expMonth.size());
        expMonth.clear();
        return *this;
    }

    CardItem& CardItem::SetExpYear(std::string& expYear) {
        if (!init) return *this;
        if (!data.contains("card") || !data["card"].is_object()) return *this;
        fieldData["ExpYear"] = localVault.Encrypt(expYear, itemEncKey, itemMacKey);
        data["card"]["expYear"] = localVault.Encrypt(expYear, itemEncKey, itemMacKey);
        OPENSSL_cleanse(expYear.data(), expYear.size());
        expYear.clear();
        return *this;
    }

    CardItem& CardItem::SetNumber(std::string& number) {
        if (!init) return *this;
        if (!data.contains("card") || !data["card"].is_object()) return *this;
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

    CardItem& CardItem::RemoveField(std::string& name) {
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
        if (data["favorite"].is_null()) return *this;
        val = data["favorite"];
        return *this;
    }

    CardItem& CardItem::GetReprompt(bool& val) {
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
        if (!data["name"].is_string()) return *this;
        name = localVault.Decrypt(data["name"], itemEncKey, itemMacKey);
        return *this;
    }

    CardItem& CardItem::GetBrand(std::string& brand) {
        if (!init) return *this;
        if (!data["card"].is_object()) return *this;
        if (!data["card"].contains("brand")) return *this;
        if (!data["card"]["brand"].is_string()) return *this;
        brand = localVault.Decrypt(data["card"]["brand"], itemEncKey, itemMacKey);
        return *this;
    }

    CardItem& CardItem::GetCardholderName(std::string& cardholderName) {
        if (!init) return *this;
        if (!data["card"].is_object()) return *this;
        if (!data["card"].contains("cardholderName")) return *this;
        if (!data["card"]["cardholderName"].is_string()) return *this;
        cardholderName = localVault.Decrypt(data["card"]["cardholderName"], itemEncKey, itemMacKey);
        return *this;
    }

    CardItem& CardItem::GetCode(std::string& code) {
        if (!init) return *this;
        if (!data["card"].is_object()) return *this;
        if (!data["card"].contains("code")) return *this;
        if (!data["card"]["code"].is_string()) return *this;
        code = localVault.Decrypt(data["card"]["code"], itemEncKey, itemMacKey);
        return *this;
    }

    CardItem& CardItem::GetExpMonth(std::string& expMonth) {
        if (!init) return *this;
        if (!data["card"].is_object()) return *this;
        if (!data["card"].contains("expMonth")) return *this;
        if (!data["card"]["expMonth"].is_string()) return *this;
        expMonth = localVault.Decrypt(data["card"]["expMonth"], itemEncKey, itemMacKey);
        return *this;
    }

    CardItem& CardItem::GetExpYear(std::string& expYear) {
        if (!init) return *this;
        if (!data["card"].is_object()) return *this;
        if (!data["card"].contains("expYear")) return *this;
        if (!data["card"]["expYear"].is_string()) return *this;
        expYear = localVault.Decrypt(data["card"]["expYear"], itemEncKey, itemMacKey);
        return *this;
    }

    CardItem& CardItem::GetNumber(std::string& number) {
        if (!init) return *this;
        if (!data["card"].is_object()) return *this;
        if (!data["card"].contains("number")) return *this;
        if (!data["card"]["number"].is_string()) return *this;
        number = localVault.Decrypt(data["card"]["number"], itemEncKey, itemMacKey);
        return *this;
    }

    CardItem& CardItem::GetNotes(std::string& notes) {
        if (!init) return *this;
        if (!data.contains("notes")) return *this;
        if (!data["notes"].is_string()) return *this;
        notes = localVault.Decrypt(data["notes"], itemEncKey, itemMacKey);
        return *this;
    }

    CardItem& CardItem::GetFolder(std::string& folder) {
        if (!init) return *this;
        if (!data.contains("folderId")) return *this;
        if (!data["folderId"].is_string()) return *this;
        folder = data["folderId"].is_null() ? "" : data["folderId"].get<std::string>();
        return *this;
    }

    CardItem& CardItem::GetFields(std::vector<std::tuple<CustomFieldType, std::string, std::string>>& fields) {
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

    CardItem& CardItem::Duplicate(std::string& id) {
        if (!logger) {
            logger = spdlog::stdout_color_mt("ClientWarden::Vault::CardItem");
        }
        auto keys = localVault.generateEncMacKeys();
        auto newitemEncKey = keys.first;
        auto newitemMacKey = keys.second;

        /*
         * SECRET DATA
        */
        std::string oldName;
        std::string oldBrand;
        std::string oldCardholderName;
        std::string oldCode;
        std::string oldExpMonth;
        std::string oldExpYear;
        std::string oldNumber;
        std::string oldNotes;
        std::vector<std::tuple<CustomFieldType, std::string, std::string>> oldFields;

        bool oldFavorite = false;
        int oldReprompt = 0;

        if (data.contains("name") && data["name"].is_string()) {
            oldName = localVault.Decrypt(data["name"], itemEncKey, itemMacKey);
        }

        if (data.contains("card") && data["card"].is_object()) {
            if (data["card"].contains("brand") && data["card"]["brand"].is_string()) {
                oldBrand = localVault.Decrypt(data["card"]["brand"], itemEncKey, itemMacKey);
            }
            if (data["card"].contains("cardholderName") && data["card"]["cardholderName"].is_string()) {
                oldCardholderName = localVault.Decrypt(data["card"]["cardholderName"], itemEncKey, itemMacKey);
            }
            if (data["card"].contains("code") && data["card"]["code"].is_string()) {
                oldCode = localVault.Decrypt(data["card"]["code"], itemEncKey, itemMacKey);
            }
            if (data["card"].contains("expMonth") && data["card"]["expMonth"].is_string()) {
                oldExpMonth = localVault.Decrypt(data["card"]["expMonth"], itemEncKey, itemMacKey);
            }
            if (data["card"].contains("expYear") && data["card"]["expYear"].is_string()) {
                oldExpYear = localVault.Decrypt(data["card"]["expYear"], itemEncKey, itemMacKey);
            }
            if (data["card"].contains("number") && data["card"]["number"].is_string()) {
                oldNumber = localVault.Decrypt(data["card"]["number"], itemEncKey, itemMacKey);
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
        newdata["card"] = nlohmann::json::object();
        newdata["card"]["brand"] = localVault.Encrypt(oldBrand, newitemEncKey, newitemMacKey);
        newdata["card"]["cardholderName"] = localVault.Encrypt(oldCardholderName, newitemEncKey, newitemMacKey);
        newdata["card"]["code"] = localVault.Encrypt(oldCode, newitemEncKey, newitemMacKey);
        newdata["card"]["expMonth"] = localVault.Encrypt(oldExpMonth, newitemEncKey, newitemMacKey);
        newdata["card"]["expYear"] = localVault.Encrypt(oldExpYear, newitemEncKey, newitemMacKey);
        newdata["card"]["number"] = localVault.Encrypt(oldNumber, newitemEncKey, newitemMacKey);
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
        newdata["sshKey"] = nullptr;
        newdata["type"] = 3;
        newdata["viewPassword"] = true;

        newfieldData["CardholderName"] = localVault.Encrypt(oldCardholderName, newitemEncKey, newitemMacKey);
        newfieldData["Brand"] = localVault.Encrypt(oldBrand, newitemEncKey, newitemMacKey);
        newfieldData["Number"] = localVault.Encrypt(oldNumber, newitemEncKey, newitemMacKey);
        newfieldData["ExpMonth"] = localVault.Encrypt(oldExpMonth, newitemEncKey, newitemMacKey);
        newfieldData["ExpYear"] = localVault.Encrypt(oldExpYear, newitemEncKey, newitemMacKey);
        newfieldData["Code"] = localVault.Encrypt(oldCode, newitemEncKey, newitemMacKey);
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
        OPENSSL_cleanse(oldBrand.data(), oldBrand.size());
        oldBrand.clear();
        OPENSSL_cleanse(oldCardholderName.data(), oldCardholderName.size());
        oldCardholderName.clear();
        OPENSSL_cleanse(oldCode.data(), oldCode.size());
        oldCode.clear();
        OPENSSL_cleanse(oldExpMonth.data(), oldExpMonth.size());
        oldExpMonth.clear();
        OPENSSL_cleanse(oldExpYear.data(), oldExpYear.size());
        oldExpYear.clear();
        OPENSSL_cleanse(oldNumber.data(), oldNumber.size());
        oldNumber.clear();
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
            spdlog::warn("Failed to add New Item Online");
            newdata["createdOffline"] = true;
        }
        localVault.vaultData["ciphers"].push_back(newdata);
        localVault.storage.write("vault.json", localVault.vaultData.dump(2));

        id = newdata["id"];

        return *this;
    }

    CardItem& CardItem::GetId(std::string& value) {
        value = data["id"];

        return *this;
    }
}