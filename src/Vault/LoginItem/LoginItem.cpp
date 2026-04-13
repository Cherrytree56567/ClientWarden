#include "LoginItem.h"

LoginItem::LoginItem(Vault& vault, std::string uuid) : localVault(vault), isBeingCreated(false) {
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
    }
}

LoginItem::LoginItem(Vault& vault) : localVault(vault), isBeingCreated(true) {
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
    data["login"] = nlohmann::json::object();
    data["login"]["autofillOnPageLoad"] = nullptr;
    data["login"]["fido2Credentials"] = nullptr;
    data["login"]["password"] = localVault.Encrypt("", itemEncKey, itemMacKey);
    data["login"]["passwordRevisionDate"] = nullptr;
    data["login"]["totp"] = localVault.Encrypt("", itemEncKey, itemMacKey);
    data["login"]["uri"] = localVault.Encrypt("", itemEncKey, itemMacKey);
    data["login"]["uris"] = nlohmann::json::array();
    data["login"]["username"] = localVault.Encrypt("", itemEncKey, itemMacKey);
    data["name"] = localVault.Encrypt("", itemEncKey, itemMacKey);
    data["notes"] = localVault.Encrypt("", itemEncKey, itemMacKey);
    data["object"] = "cipherDetails";
    data["organizationId"] = nullptr;
    data["organizationUseTotp"] = nullptr;
    data["passwordHistory"] = nlohmann::json::array();
    data["permissions"] = nlohmann::json::object();
    data["permissions"]["delete"] = true;
    data["permissions"]["restore"] = true;
    data["reprompt"] = 0;
    data["revisionDate"] = nullptr;
    data["secureNote"] = nullptr;
    data["sshKey"] = nullptr;
    data["type"] = 1;
    data["viewPassword"] = true;

    fieldData["Fields"] = nlohmann::json::array();
    fieldData["Name"] = localVault.Encrypt("", itemEncKey, itemMacKey);
    fieldData["Notes"] = localVault.Encrypt("", itemEncKey, itemMacKey);
    fieldData["Password"] = localVault.Encrypt("", itemEncKey, itemMacKey);
    fieldData["PasswordHistory"] = nullptr;
    fieldData["PasswordRevisionDate"] = nullptr;
    fieldData["Uris"] = nlohmann::json::array();
    fieldData["Username"] = localVault.Encrypt("", itemEncKey, itemMacKey);
}

LoginItem::~LoginItem() {
    /*
     * TODO: Destruct
    */
    OPENSSL_cleanse(itemEncKey.data(), itemEncKey.size());
    itemEncKey.clear();
    OPENSSL_cleanse(itemMacKey.data(), itemMacKey.size());
    itemMacKey.clear();
}

LoginItem& LoginItem::SetName(std::string& name) {
    fieldData["Name"] = localVault.Encrypt(name, itemEncKey, itemMacKey);
    data["name"] = localVault.Encrypt(name, itemEncKey, itemMacKey);
    OPENSSL_cleanse(name.data(), name.size());
    name.clear();
    return *this;
}

LoginItem& LoginItem::SetUsername(std::string& username) {
    fieldData["Username"] = localVault.Encrypt(username, itemEncKey, itemMacKey);
    data["login"]["username"] = localVault.Encrypt(username, itemEncKey, itemMacKey);
    OPENSSL_cleanse(username.data(), username.size());
    username.clear();
    return *this;
}

LoginItem& LoginItem::SetPassword(std::string& password) {
    fieldData["Password"] = localVault.Encrypt(password, itemEncKey, itemMacKey);
    data["login"]["password"] = localVault.Encrypt(password, itemEncKey, itemMacKey);
    OPENSSL_cleanse(password.data(), password.size());
    password.clear();
    return *this;
}

LoginItem& LoginItem::SetTotp(std::string& totp) {
    fieldData["Totp"] = localVault.Encrypt(totp, itemEncKey, itemMacKey);
    data["login"]["totp"] = localVault.Encrypt(totp, itemEncKey, itemMacKey);
    OPENSSL_cleanse(totp.data(), totp.size());
    totp.clear();
    return *this;
}

LoginItem& LoginItem::SetNotes(std::string& notes) {
    fieldData["Notes"] = localVault.Encrypt(notes, itemEncKey, itemMacKey);
    data["notes"] = localVault.Encrypt(notes, itemEncKey, itemMacKey);
    OPENSSL_cleanse(notes.data(), notes.size());
    notes.clear();
    return *this;
}

LoginItem& LoginItem::SetFolder(std::string folderUUID) {
    data["folderId"] = folderUUID;
    return *this;
}

LoginItem& LoginItem::RemoveFolder() {
    data["folderId"] = nullptr;
    return *this;
}

LoginItem& LoginItem::AddWebsite(std::string& website) {
    nlohmann::json uriData;
    uriData["match"] = nullptr;
    uriData["uri"] = localVault.Encrypt(website, itemEncKey, itemMacKey);
    uriData["uriChecksum"] = localVault.getUriChecksum(website, itemEncKey, itemMacKey);

    nlohmann::json dataUriField;
    dataUriField["Uri"] = localVault.Encrypt(website, itemEncKey, itemMacKey);
    dataUriField["UriChecksum"] = localVault.getUriChecksum(website, itemEncKey, itemMacKey);

    fieldData["Uris"].push_back(dataUriField);
    data["login"]["uris"].push_back(uriData);
    OPENSSL_cleanse(website.data(), website.size());
    website.clear();
    return *this;
}

LoginItem& LoginItem::RemoveWebsite(std::string& website) {
    std::string decUri = localVault.Decrypt(data["login"]["uri"], itemEncKey, itemMacKey);
    if (decUri == website) {
        data["login"]["uri"] = nullptr;
    }

    OPENSSL_cleanse(decUri.data(), decUri.size());
    decUri.clear();

    auto& uris = data["login"]["uris"];
    for (auto it = uris.begin(); it != uris.end(); ++it) {
        std::string decWeb = localVault.Decrypt((*it)["uri"], itemEncKey, itemMacKey);
        if (decWeb == website) {
            OPENSSL_cleanse(decWeb.data(), decWeb.size());
            decWeb.clear();
            uris.erase(it);
            break;
        }

        OPENSSL_cleanse(decWeb.data(), decWeb.size());
        decWeb.clear();
    }

    auto& urisField = fieldData["Uris"];
    for (auto it = urisField.begin(); it != urisField.end(); ++it) {
        std::string decWeb = localVault.Decrypt((*it)["Uri"], itemEncKey, itemMacKey);
        if (decWeb == website) {
            OPENSSL_cleanse(decWeb.data(), decWeb.size());
            decWeb.clear();
            urisField.erase(it);
            break;
        }

        OPENSSL_cleanse(decWeb.data(), decWeb.size());
        decWeb.clear();
    }

    OPENSSL_cleanse(website.data(), website.size());
    website.clear();
    return *this;
}

LoginItem& LoginItem::AddField(CustomFieldType field, std::string& name, std::string& value) {
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

LoginItem& LoginItem::RemoveField(std::string& name) {
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

void LoginItem::Commit() {
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
}

void LoginItem::Delete() {
    if (!isBeingCreated) {
        OPENSSL_cleanse(itemEncKey.data(), itemEncKey.size());
        itemEncKey.clear();
        OPENSSL_cleanse(itemMacKey.data(), itemMacKey.size());
        itemMacKey.clear();
        auto& ciphers = localVault.vaultData["ciphers"];
        auto it = std::find_if(ciphers.begin(), ciphers.end(), [&](const nlohmann::json& cipher) {
            return cipher["id"] == data["id"];
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
}