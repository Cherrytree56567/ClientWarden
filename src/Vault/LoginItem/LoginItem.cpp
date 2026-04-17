#include "LoginItem.h"

namespace ClientWarden::Vault {
    LoginItem::LoginItem(Vault& vault, std::string uuid) : localVault(vault), isBeingCreated(false) {
        logger = spdlog::stdout_color_mt("ClientWarden::Vault::LoginItem");
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

    LoginItem::LoginItem(Vault& vault) : localVault(vault), isBeingCreated(true) {
        logger = spdlog::stdout_color_mt("ClientWarden::Vault::LoginItem");
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
        data["login"]["password"] = nullptr;
        data["login"]["passwordRevisionDate"] = nullptr;
        data["login"]["totp"] = nullptr;
        data["login"]["uri"] = nullptr;
        data["login"]["uris"] = nlohmann::json::array();
        data["login"]["username"] = nullptr;
        data["name"] = localVault.Encrypt("", itemEncKey, itemMacKey);
        data["notes"] = nullptr;
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
        fieldData["Notes"] = nullptr;
        fieldData["Password"] = nullptr;
        fieldData["PasswordHistory"] = nullptr;
        fieldData["PasswordRevisionDate"] = nullptr;
        fieldData["Uris"] = nlohmann::json::array();
        fieldData["Username"] = nullptr;

        init = true;
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
        if (!init) return *this;
        fieldData["Name"] = localVault.Encrypt(name, itemEncKey, itemMacKey);
        data["name"] = localVault.Encrypt(name, itemEncKey, itemMacKey);
        OPENSSL_cleanse(name.data(), name.size());
        name.clear();
        return *this;
    }

    LoginItem& LoginItem::SetUsername(std::string& username) {
        if (!init) return *this;
        fieldData["Username"] = localVault.Encrypt(username, itemEncKey, itemMacKey);
        data["login"]["username"] = localVault.Encrypt(username, itemEncKey, itemMacKey);
        OPENSSL_cleanse(username.data(), username.size());
        username.clear();
        return *this;
    }

    LoginItem& LoginItem::SetPassword(std::string& password) {
        if (!init) return *this;
        fieldData["Password"] = localVault.Encrypt(password, itemEncKey, itemMacKey);
        data["login"]["password"] = localVault.Encrypt(password, itemEncKey, itemMacKey);
        OPENSSL_cleanse(password.data(), password.size());
        password.clear();
        return *this;
    }

    LoginItem& LoginItem::SetTotp(std::string& totp) {
        if (!init) return *this;
        fieldData["Totp"] = localVault.Encrypt(totp, itemEncKey, itemMacKey);
        data["login"]["totp"] = localVault.Encrypt(totp, itemEncKey, itemMacKey);
        OPENSSL_cleanse(totp.data(), totp.size());
        totp.clear();
        return *this;
    }

    LoginItem& LoginItem::SetNotes(std::string& notes) {
        if (!init) return *this;
        fieldData["Notes"] = localVault.Encrypt(notes, itemEncKey, itemMacKey);
        data["notes"] = localVault.Encrypt(notes, itemEncKey, itemMacKey);
        OPENSSL_cleanse(notes.data(), notes.size());
        notes.clear();
        return *this;
    }

    LoginItem& LoginItem::SetFolder(std::string folderUUID) {
        if (!init) return *this;
        data["folderId"] = folderUUID;
        return *this;
    }

    LoginItem& LoginItem::RemoveFolder() {
        if (!init) return *this;
        data["folderId"] = nullptr;
        return *this;
    }

    LoginItem& LoginItem::AddWebsite(std::string& website) {
        if (!init) return *this;
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
        if (!init) return *this;
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

    LoginItem& LoginItem::RemoveField(std::string& name) {
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

    void LoginItem::Commit() {
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

    void LoginItem::Delete() {
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

    void LoginItem::Close() {
        if (!init) return;
        OPENSSL_cleanse(itemEncKey.data(), itemEncKey.size());
        itemEncKey.clear();
        OPENSSL_cleanse(itemMacKey.data(), itemMacKey.size());
        itemMacKey.clear();

        localVault.storage.write("vault.json", localVault.vaultData.dump(2));
    }

    void LoginItem::Bin() {
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

    LoginItem& LoginItem::GetName(std::string& name) {
        if (!init) return *this;
        if (!data.contains("name")) return *this;
        name = localVault.Decrypt(data["name"], itemEncKey, itemMacKey);
        return *this;
    }

    LoginItem& LoginItem::GetUsername(std::string& username) {
        if (!init) return *this;
        if (!data["login"].contains("username")) return *this;
        username = localVault.Decrypt(data["login"]["username"], itemEncKey, itemMacKey);
        return *this;
    }

    LoginItem& LoginItem::GetPassword(std::string& password) {
        if (!init) return *this;
        if (!data["login"].contains("password")) return *this;
        password = localVault.Decrypt(data["login"]["password"], itemEncKey, itemMacKey);
        return *this;
    }

    LoginItem& LoginItem::GetTotp(TOTPCode& totp) {
        if (!init) return *this;
        if (!data["login"].contains("totp")) return *this;

        std::string totpURI = localVault.Decrypt(data["login"]["totp"], itemEncKey, itemMacKey);

        boost::urls::url_view uri(totpURI);

        auto params = uri.params();
        
        std::string secret;
        std::string algo;
        int digits;
        int period;

        for (auto p : params) {
            if (p.key == "secret") {
                secret = p.value;
            } else if (p.key == "algorithm") {
                algo = p.value;
            } else if (p.key == "digits") {
                digits = std::stoi(p.value);
            } else if (p.key == "period") {
                period = std::stoi(p.value);
            }
        }

        OPENSSL_cleanse(totpURI.data(), totpURI.size());

        Botan::secure_vector<uint8_t> secureSecret = Botan::base32_decode(secret);

        //OPENSSL_cleanse(secret.data(), secret.size());

        if (algo == "sha256" || algo == "SHA256") {
            algo = "SHA-256";
        } else if (algo == "sha512" || algo == "SHA512") {
            algo = "SHA-512";
        } else {
            algo = "SHA-1";
        }

        if (digits > 8 || digits < 6) {
            digits = 6;
        }

        logger->info("Secret: {}, Algo: {}, Digits: {}, Period: {}", secret, algo, digits, period);

        Botan::TOTP totpCode(secureSecret.data(), secureSecret.size(), algo, digits, period);

        uint32_t code = totpCode.generate_totp(std::chrono::system_clock::now());

        std::time_t now = std::time(nullptr);

        std::time_t currentStep = (now / period) * period;
        std::time_t nextRefresh = currentStep + period;

        std::ostringstream oss;
        oss << std::setw(digits) << std::setfill('0') << code;
        totp.code = oss.str();
        totp.remaining = nextRefresh;

        return *this;
    }

    LoginItem& LoginItem::GetNotes(std::string& notes) {
        if (!init) return *this;
        if (!data.contains("notes")) return *this;
        notes = localVault.Decrypt(data["notes"], itemEncKey, itemMacKey);
        return *this;
    }

    LoginItem& LoginItem::GetFolder(std::string& folder) {
        if (!init) return *this;
        if (!data.contains("folderId")) return *this;
        folder = data["folderId"].is_null() ? "" : data["folderId"].get<std::string>();
        return *this;
    }

    LoginItem& LoginItem::GetWebsites(std::vector<std::string>& websites) {
        if (!init) return *this;
        if (!data["login"].contains("uris")) return *this;
        websites.clear();
        for (auto& uri : data["login"]["uris"]) {
            websites.push_back(localVault.Decrypt(uri["uri"], itemEncKey, itemMacKey));
        }
        return *this;
    }

    LoginItem& LoginItem::GetFields(std::vector<std::tuple<CustomFieldType, std::string, std::string>>& fields) {
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

    LoginItem& LoginItem::GetPasswordHistory(std::vector<std::pair<std::time_t, std::string>>& value) {
        if (!init) return *this;
        if (!data["login"].contains("passwordRevisionDate")) return *this;
        if (!data.contains("passwordHistory")) return *this;
        if (!data["login"]["passwordRevisionDate"].is_null()) {
            for (auto& revHist : data["passwordHistory"]) {
                if (!revHist.contains("lastUsedDate")) continue;
                if (!revHist.contains("password")) continue;
                std::time_t revTime = BitwardenTime(revHist["lastUsedDate"]);
                std::string password = localVault.Decrypt(revHist["password"], itemEncKey, itemMacKey);
                value.emplace_back(std::move(revTime), std::move(password));
            }
        }
        return *this;
    }

    LoginItem& LoginItem::SetFavorite(bool val) {
        if (!init) return *this;
        data["favorite"] = val;
        return *this;
    }

    LoginItem& LoginItem::SetReprompt(bool val) {
        if (!init) return *this;
        if (val) {
            data["reprompt"] = 1;
        } else {
            data["reprompt"] = 0;
        }
        return *this;
    }

    LoginItem& LoginItem::GetFavorite(bool& val) {
        if (!init) return *this;
        if (!data.contains("favorite")) return *this;
        val = data["favorite"];
        return *this;
    }

    LoginItem& LoginItem::GetReprompt(bool& val) {
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