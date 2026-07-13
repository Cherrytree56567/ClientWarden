#include "LoginItem.h"
#include "Vault.h"

namespace ClientWarden {
    LoginItem::LoginItem(Vault& vault, std::string uuid) : GenericItemImpl<LoginItem>(vault, uuid) {
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

    LoginItem::LoginItem(Vault& vault) : GenericItemImpl<LoginItem>(vault) {
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
        data["login"] = nlohmann::json::object();
        data["login"]["autofillOnPageLoad"] = nullptr;
        data["login"]["fido2Credentials"] = nullptr;
        data["login"]["password"] = nullptr;
        data["login"]["passwordRevisionDate"] = nullptr;
        data["login"]["totp"] = nullptr;
        data["login"]["uri"] = nullptr;
        data["login"]["uris"] = nlohmann::json::array();
        data["login"]["username"] = nullptr;
        data["name"] = localVault.crypto.Encrypt("", itemEncKey, itemMacKey);
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
        fieldData["Name"] = localVault.crypto.Encrypt("", itemEncKey, itemMacKey);
        fieldData["Notes"] = nullptr;
        fieldData["Password"] = nullptr;
        fieldData["PasswordHistory"] = nullptr;
        fieldData["PasswordRevisionDate"] = nullptr;
        fieldData["Uris"] = nlohmann::json::array();
        fieldData["Username"] = nullptr;
        fieldData["Totp"] = nullptr;

        init = true;
    }

    LoginItem* LoginItem::Duplicate(std::string& id) {
        auto keys = localVault.crypto.generateEncMacKeys();
        auto newitemEncKey = keys.first;
        auto newitemMacKey = keys.second;

        /*
         * SECRET DATA
        */
        std::string oldName;
        std::string oldUsername;
        std::string oldPassword;
        std::string oldTOTP;
        std::string oldNotes;
        std::string olduri = "";
        std::vector<std::string> oldWebsites;
        std::vector<std::tuple<CustomFieldType, std::string, std::string>> oldFields;

        bool oldFavorite = false;
        int oldReprompt = 0;

        if (data.contains("name") && data["name"].is_string()) {
            oldName = localVault.crypto.DecryptAsStr(data["name"], itemEncKey, itemMacKey);
        }

        if (data.contains("login") && data["login"].is_object()) {
            if (data["login"].contains("username") && data["login"]["username"].is_string()) {
                oldUsername = localVault.crypto.DecryptAsStr(data["login"]["username"], itemEncKey, itemMacKey);
            }
            if (data["login"].contains("password") && data["login"]["password"].is_string()) {
                oldPassword = localVault.crypto.DecryptAsStr(data["login"]["password"], itemEncKey, itemMacKey);
            }
            if (data["login"].contains("totp") && data["login"]["totp"].is_string()) {
                oldTOTP = localVault.crypto.DecryptAsStr(data["login"]["totp"], itemEncKey, itemMacKey);
            }
            if (data["login"].contains("uris") && data["login"]["uris"].is_array()) {
                if (data["login"]["uris"].size() > 0) {
                    olduri = localVault.crypto.DecryptAsStr(data["login"]["uris"][0]["uri"], itemEncKey, itemMacKey);
                }
                for (auto& web : data["login"]["uris"]) {
                    oldWebsites.push_back(localVault.crypto.DecryptAsStr(web["uri"], itemEncKey, itemMacKey));
                }
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
        newdata["login"] = nlohmann::json::object();
        newdata["login"]["autofillOnPageLoad"] = nullptr;
        newdata["login"]["fido2Credentials"] = nullptr;
        newdata["login"]["password"] = localVault.crypto.Encrypt(oldPassword, newitemEncKey, newitemMacKey);
        newdata["login"]["passwordRevisionDate"] = nullptr;
        newdata["login"]["totp"] = localVault.crypto.Encrypt(oldTOTP, newitemEncKey, newitemMacKey);
        if (olduri != "") {
            newdata["login"]["uri"] = localVault.crypto.Encrypt(olduri, newitemEncKey, newitemMacKey);
        } else {
            newdata["login"]["uri"] = nullptr;
        }
        newdata["login"]["uris"] = nlohmann::json::array();
        newdata["login"]["username"] = localVault.crypto.Encrypt(oldUsername, newitemEncKey, newitemMacKey);
        newdata["name"] = localVault.crypto.Encrypt(oldName, newitemEncKey, newitemMacKey);
        newdata["notes"] = localVault.crypto.Encrypt(oldNotes, newitemEncKey, newitemMacKey);
        newdata["object"] = "cipherDetails";
        newdata["organizationId"] = nullptr;
        newdata["organizationUseTotp"] = nullptr;
        newdata["passwordHistory"] = nlohmann::json::array();
        newdata["permissions"] = nlohmann::json::object();
        newdata["permissions"]["delete"] = true;
        newdata["permissions"]["restore"] = true;
        newdata["reprompt"] = oldReprompt;
        newdata["revisionDate"] = nullptr;
        newdata["secureNote"] = nullptr;
        newdata["sshKey"] = nullptr;
        newdata["type"] = 1;
        newdata["viewPassword"] = true;

        newfieldData["Fields"] = nlohmann::json::array();
        newfieldData["Name"] = localVault.crypto.Encrypt(oldName, newitemEncKey, newitemMacKey);
        newfieldData["Notes"] = localVault.crypto.Encrypt(oldNotes, newitemEncKey, newitemMacKey);
        newfieldData["Password"] = localVault.crypto.Encrypt(oldPassword, newitemEncKey, newitemMacKey);
        newfieldData["PasswordHistory"] = nullptr;
        newfieldData["PasswordRevisionDate"] = nullptr;
        newfieldData["Uris"] = nlohmann::json::array();
        newfieldData["Username"] = localVault.crypto.Encrypt(oldUsername, newitemEncKey, newitemMacKey);
        newfieldData["Totp"] = localVault.crypto.Encrypt(oldTOTP, newitemEncKey, newitemMacKey);

        for (auto& web : oldWebsites) {
            nlohmann::json uriData;
            uriData["match"] = nullptr;
            uriData["uri"] = localVault.crypto.Encrypt(web, newitemEncKey, newitemMacKey);
            uriData["uriChecksum"] = localVault.crypto.getUriChecksum(web, newitemEncKey, newitemMacKey);

            nlohmann::json dataUriField;
            dataUriField["Uri"] = localVault.crypto.Encrypt(web, newitemEncKey, newitemMacKey);
            dataUriField["UriChecksum"] = localVault.crypto.getUriChecksum(web, newitemEncKey, newitemMacKey);

            newfieldData["Uris"].push_back(dataUriField);
            newdata["login"]["uris"].push_back(uriData);

            OPENSSL_cleanse(web.data(), web.size());
            web.clear();
        }

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
        OPENSSL_cleanse(oldUsername.data(), oldUsername.size());
        oldUsername.clear();
        OPENSSL_cleanse(oldPassword.data(), oldPassword.size());
        oldPassword.clear();
        OPENSSL_cleanse(oldTOTP.data(), oldTOTP.size());
        oldTOTP.clear();
        OPENSSL_cleanse(oldNotes.data(), oldNotes.size());
        oldNotes.clear();
        OPENSSL_cleanse(olduri.data(), olduri.size());
        olduri.clear();
        Botan::secure_scrub_memory(newitemEncKey.data(), newitemEncKey.size());
        Botan::secure_scrub_memory(newitemMacKey.data(), newitemMacKey.size());

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

    LoginItem* LoginItem::SetUsername(std::string& username) {
        if (!init) return this;
        if (!data.contains("login") || !data["login"].is_object()) return this;
        fieldData["Username"] = localVault.crypto.Encrypt(username, itemEncKey, itemMacKey);
        data["login"]["username"] = localVault.crypto.Encrypt(username, itemEncKey, itemMacKey);
        OPENSSL_cleanse(username.data(), username.size());
        username.clear();
        return this;
    }

    LoginItem* LoginItem::SetPassword(std::string& password) {
        if (!init) return this;
        if (!data.contains("login") || !data["login"].is_object()) return this;
        fieldData["Password"] = localVault.crypto.Encrypt(password, itemEncKey, itemMacKey);
        data["login"]["password"] = localVault.crypto.Encrypt(password, itemEncKey, itemMacKey);
        OPENSSL_cleanse(password.data(), password.size());
        password.clear();
        return this;
    }

    LoginItem* LoginItem::SetTotp(std::string& totp) {
        if (!init) return this;
        if (!data.contains("login") || !data["login"].is_object()) return this;
        fieldData["Totp"] = localVault.crypto.Encrypt(totp, itemEncKey, itemMacKey);
        data["login"]["totp"] = localVault.crypto.Encrypt(totp, itemEncKey, itemMacKey);
        OPENSSL_cleanse(totp.data(), totp.size());
        totp.clear();
        return this;
    }

    LoginItem* LoginItem::AddWebsite(std::string& website) {
        if (!init) return this;
        if (!data.contains("login") || !data["login"].is_object()) return this;
        nlohmann::json uriData;
        uriData["match"] = nullptr;
        uriData["uri"] = localVault.crypto.Encrypt(website, itemEncKey, itemMacKey);
        uriData["uriChecksum"] = localVault.crypto.getUriChecksum(website, itemEncKey, itemMacKey);

        nlohmann::json dataUriField;
        dataUriField["Uri"] = localVault.crypto.Encrypt(website, itemEncKey, itemMacKey);
        dataUriField["UriChecksum"] = localVault.crypto.getUriChecksum(website, itemEncKey, itemMacKey);

        fieldData["Uris"].push_back(dataUriField);
        data["login"]["uris"].push_back(uriData);
        OPENSSL_cleanse(website.data(), website.size());
        website.clear();
        return this;
    }

    LoginItem* LoginItem::RemoveWebsite(std::string& website) {
        if (!init) return this;
        if (!data.contains("login") || !data["login"].is_object()) return this;
        if (!data["login"].contains("uri") || !data["login"].contains("uris")) return this;
        if (data["login"]["uri"].is_string())  {
            std::string decUri = localVault.crypto.DecryptAsStr(data["login"]["uri"], itemEncKey, itemMacKey);
            if (decUri == website) {
                data["login"]["uri"] = nullptr;
            }

            OPENSSL_cleanse(decUri.data(), decUri.size());
            decUri.clear();
        }

        auto& uris = data["login"]["uris"];
        for (auto it = uris.begin(); it != uris.end(); ++it) {
            std::string decWeb = localVault.crypto.DecryptAsStr((*it)["uri"], itemEncKey, itemMacKey);
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
            std::string decWeb = localVault.crypto.DecryptAsStr((*it)["Uri"], itemEncKey, itemMacKey);
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
        return this;
    }

    LoginItem* LoginItem::GetUsername(std::string& username) {
        if (!init) return this;
        if (!data["login"].is_object()) return this;
        if (!data["login"].contains("username")) return this;
        if (!data["login"]["username"].is_string()) return this;
        username = localVault.crypto.DecryptAsStr(data["login"]["username"], itemEncKey, itemMacKey);
        return this;
    }

    LoginItem* LoginItem::GetPassword(std::string& password) {
        if (!init) return this;
        if (!data["login"].is_object()) return this;
        if (!data["login"].contains("password")) return this;
        if (!data["login"]["password"].is_string()) return this;
        password = localVault.crypto.DecryptAsStr(data["login"]["password"], itemEncKey, itemMacKey);
        return this;
    }

    LoginItem* LoginItem::GetTotpSecret(std::string& totp) {
        if (!init) return this;
        if (!data["login"].is_object()) return this;
        if (!data["login"].contains("totp")) return this;
        if (!data["login"]["totp"].is_string()) return this;

        totp = localVault.crypto.DecryptAsStr(data["login"]["totp"], itemEncKey, itemMacKey);

        return this;
    }

    LoginItem* LoginItem::GetTotp(TOTPCode& totp) {
        if (!init) return this;
        if (!data["login"].is_object()) return this;
        if (!data["login"].contains("totp")) return this;
        if (!data["login"]["totp"].is_string()) return this;

        try {
            std::string totpURI = localVault.crypto.DecryptAsStr(data["login"]["totp"], itemEncKey, itemMacKey);

            if (totpURI == "") return this;

            boost::urls::url_view uri(totpURI);

            auto params = uri.params();
            
            std::string secret = "";
            std::string algo = "";
            int digits = 0;
            int period = 0;

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

            if (secret == "" || algo == "" || digits == 0 || period == 0) {
                secret = totpURI;
                digits = 6;
                period = 30;
            }

            OPENSSL_cleanse(totpURI.data(), totpURI.size());

            Botan::secure_vector<uint8_t> secureSecret = Botan::base32_decode(secret);

            OPENSSL_cleanse(secret.data(), secret.size());

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

            Botan::TOTP totpCode(secureSecret.data(), secureSecret.size(), algo, digits, period);

            uint32_t code = totpCode.generate_totp(std::chrono::system_clock::now());

            std::time_t now = std::time(nullptr);

            std::time_t currentStep = (now / period) * period;
            std::time_t nextRefresh = currentStep + period;

            std::ostringstream oss;
            oss << std::setw(digits) << std::setfill('0') << code;
            totp.code = oss.str();
            totp.remaining = nextRefresh;
            totp.period = period;
        } catch (...) {
            logger->info("Failed to get TOTP");
            return this;
        }

        return this;
    }

    LoginItem* LoginItem::GetWebsites(std::vector<std::string>& websites) {
        if (!init) return this;
        if (!data["login"].contains("uris")) return this;
        if (!data["login"]["uris"].is_array()) return this;
        websites.clear();
        for (auto& uri : data["login"]["uris"]) {
            websites.push_back(localVault.crypto.DecryptAsStr(uri["uri"], itemEncKey, itemMacKey));
        }
        return this;
    }

    LoginItem* LoginItem::GetPasswordHistory(std::vector<std::pair<std::time_t, std::string>>& value) {
        if (!init) return this;
        if (!data["login"].contains("passwordRevisionDate")) return this;
        if (!data.contains("passwordHistory")) return this;
        if (data["passwordHistory"].is_null()) return this;
        if (!data["login"]["passwordRevisionDate"].is_null()) {
            for (auto& revHist : data["passwordHistory"]) {
                if (!revHist.contains("lastUsedDate")) continue;
                if (!revHist.contains("password")) continue;
                std::time_t revTime = BitwardenTime(revHist["lastUsedDate"]);
                std::string password = localVault.crypto.DecryptAsStr(revHist["password"], itemEncKey, itemMacKey);
                value.emplace_back(std::move(revTime), std::move(password));
            }
        }
        return this;
    }

    LoginItem* LoginItem::GetPasskeyCreationDate(std::vector<std::time_t>& value) {
        if (!init) return this;
        if (!data["login"].contains("fido2Credentials")) return this;
        if (!data["login"]["fido2Credentials"].is_array()) return this;

        for (auto& passk : data["login"]["fido2Credentials"]) {
            if (!passk.contains("creationDate")) return this;
            if (!passk["creationDate"].is_string()) return this;
            value.push_back(BitwardenTime(passk["creationDate"].get<std::string>()));
        }
        return this;
    }

    LoginItem* LoginItem::GetType(CipherType& val) {
        val = CipherType::Login;
        return this;
    }
}