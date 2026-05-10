#include "IdentityItem.h"

namespace ClientWarden::Vault {
    IdentityItem::IdentityItem(Vault& vault, std::string uuid) : localVault(vault), isBeingCreated(false) {
        if (!logger) {
            logger = spdlog::stdout_color_mt("ClientWarden::Vault::IdentityItem");
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
            if (data["type"].get<int>() == 4) {
                init = true;
            }
        }
        if (!data.contains("card")) {
            init = false;
        }
    }

    IdentityItem::IdentityItem(Vault& vault) : localVault(vault), isBeingCreated(true) {
        if (!logger) {
            logger = spdlog::stdout_color_mt("ClientWarden::Vault::IdentityItem");
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
        data["identity"] = nlohmann::json::object();
        data["identity"]["address1"] = nullptr;
        data["identity"]["address2"] = nullptr;
        data["identity"]["address3"] = nullptr;
        data["identity"]["city"] = nullptr;
        data["identity"]["company"] = nullptr;
        data["identity"]["country"] = nullptr;
        data["identity"]["email"] = nullptr;
        data["identity"]["firstName"] = nullptr;
        data["identity"]["lastName"] = nullptr;
        data["identity"]["licenseNumber"] = nullptr;
        data["identity"]["middleName"] = nullptr;
        data["identity"]["passportNumber"] = nullptr;
        data["identity"]["phone"] = nullptr;
        data["identity"]["postalCode"] = nullptr;
        data["identity"]["ssn"] = nullptr;
        data["identity"]["state"] = nullptr;
        data["identity"]["title"] = nullptr;
        data["identity"]["username"] = nullptr;
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
        data["type"] = 4;
        data["viewPassword"] = true;

        fieldData["Title"] = nullptr;
        fieldData["FirstName"] = nullptr;
        fieldData["MiddleName"] = nullptr;
        fieldData["LastName"] = nullptr;
        fieldData["Address1"] = nullptr;
        fieldData["Address2"] = nullptr;
        fieldData["Address3"] = nullptr;
        fieldData["City"] = nullptr;
        fieldData["State"] = nullptr;
        fieldData["PostalCode"] = nullptr;
        fieldData["Country"] = nullptr;
        fieldData["Company"] = nullptr;
        fieldData["Email"] = nullptr;
        fieldData["Phone"] = nullptr;
        fieldData["SSN"] = nullptr;
        fieldData["Username"] = nullptr;
        fieldData["PassportNumber"] = nullptr;
        fieldData["LicenseNumber"] = nullptr;
        fieldData["Name"] = localVault.Encrypt("", itemEncKey, itemMacKey);
        fieldData["Notes"] = nullptr;
        fieldData["Fields"] = nlohmann::json::array();

        init = true;
    }

    IdentityItem::~IdentityItem() {
        /*
        * TODO: Destruct
        */
        OPENSSL_cleanse(itemEncKey.data(), itemEncKey.size());
        itemEncKey.clear();
        OPENSSL_cleanse(itemMacKey.data(), itemMacKey.size());
        itemMacKey.clear();
    }

    IdentityItem& IdentityItem::SetName(std::string& name) {
        if (!init) return *this;
        fieldData["Name"] = localVault.Encrypt(name, itemEncKey, itemMacKey);
        data["name"] = localVault.Encrypt(name, itemEncKey, itemMacKey);
        OPENSSL_cleanse(name.data(), name.size());
        name.clear();
        return *this;
    }

    IdentityItem& IdentityItem::SetAddress1(std::string& address1) {
        if (!init) return *this;
        if (!data.contains("identity") || !data["identity"].is_object()) return *this;
        fieldData["Address1"] = localVault.Encrypt(address1, itemEncKey, itemMacKey);
        data["identity"]["address1"] = localVault.Encrypt(address1, itemEncKey, itemMacKey);
        OPENSSL_cleanse(address1.data(), address1.size());
        address1.clear();
        return *this;
    }

    IdentityItem& IdentityItem::SetAddress2(std::string& address2) {
        if (!init) return *this;
        if (!data.contains("identity") || !data["identity"].is_object()) return *this;
        fieldData["Address2"] = localVault.Encrypt(address2, itemEncKey, itemMacKey);
        data["identity"]["address2"] = localVault.Encrypt(address2, itemEncKey, itemMacKey);
        OPENSSL_cleanse(address2.data(), address2.size());
        address2.clear();
        return *this;
    }

    IdentityItem& IdentityItem::SetAddress3(std::string& address3) {
        if (!init) return *this;
        if (!data.contains("identity") || !data["identity"].is_object()) return *this;
        fieldData["Address3"] = localVault.Encrypt(address3, itemEncKey, itemMacKey);
        data["identity"]["address3"] = localVault.Encrypt(address3, itemEncKey, itemMacKey);
        OPENSSL_cleanse(address3.data(), address3.size());
        address3.clear();
        return *this;
    }

    IdentityItem& IdentityItem::SetCity(std::string& city) {
        if (!init) return *this;
        if (!data.contains("identity") || !data["identity"].is_object()) return *this;
        fieldData["City"] = localVault.Encrypt(city, itemEncKey, itemMacKey);
        data["identity"]["city"] = localVault.Encrypt(city, itemEncKey, itemMacKey);
        OPENSSL_cleanse(city.data(), city.size());
        city.clear();
        return *this;
    }

    IdentityItem& IdentityItem::SetCompany(std::string& company) {
        if (!init) return *this;
        if (!data.contains("identity") || !data["identity"].is_object()) return *this;
        fieldData["Company"] = localVault.Encrypt(company, itemEncKey, itemMacKey);
        data["identity"]["company"] = localVault.Encrypt(company, itemEncKey, itemMacKey);
        OPENSSL_cleanse(company.data(), company.size());
        company.clear();
        return *this;
    }

    IdentityItem& IdentityItem::SetCountry(std::string& country) {
        if (!init) return *this;
        if (!data.contains("identity") || !data["identity"].is_object()) return *this;
        fieldData["Country"] = localVault.Encrypt(country, itemEncKey, itemMacKey);
        data["identity"]["country"] = localVault.Encrypt(country, itemEncKey, itemMacKey);
        OPENSSL_cleanse(country.data(), country.size());
        country.clear();
        return *this;
    }

    IdentityItem& IdentityItem::SetEmail(std::string& email) {
        if (!init) return *this;
        if (!data.contains("identity") || !data["identity"].is_object()) return *this;
        fieldData["Email"] = localVault.Encrypt(email, itemEncKey, itemMacKey);
        data["identity"]["email"] = localVault.Encrypt(email, itemEncKey, itemMacKey);
        OPENSSL_cleanse(email.data(), email.size());
        email.clear();
        return *this;
    }

    IdentityItem& IdentityItem::SetFirstName(std::string& firstName) {
        if (!init) return *this;
        if (!data.contains("identity") || !data["identity"].is_object()) return *this;
        fieldData["FirstName"] = localVault.Encrypt(firstName, itemEncKey, itemMacKey);
        data["identity"]["firstName"] = localVault.Encrypt(firstName, itemEncKey, itemMacKey);
        OPENSSL_cleanse(firstName.data(), firstName.size());
        firstName.clear();
        return *this;
    }

    IdentityItem& IdentityItem::SetLastName(std::string& lastName) {
        if (!init) return *this;
        if (!data.contains("identity") || !data["identity"].is_object()) return *this;
        fieldData["LastName"] = localVault.Encrypt(lastName, itemEncKey, itemMacKey);
        data["identity"]["lastName"] = localVault.Encrypt(lastName, itemEncKey, itemMacKey);
        OPENSSL_cleanse(lastName.data(), lastName.size());
        lastName.clear();
        return *this;
    }

    IdentityItem& IdentityItem::SetLicenceNumber(std::string& licenceNumber) {
        if (!init) return *this;
        if (!data.contains("identity") || !data["identity"].is_object()) return *this;
        fieldData["LicenseNumber"] = localVault.Encrypt(licenceNumber, itemEncKey, itemMacKey);
        data["identity"]["licenseNumber"] = localVault.Encrypt(licenceNumber, itemEncKey, itemMacKey);
        OPENSSL_cleanse(licenceNumber.data(), licenceNumber.size());
        licenceNumber.clear();
        return *this;
    }

    IdentityItem& IdentityItem::SetMiddleName(std::string& middleName) {
        if (!init) return *this;
        if (!data.contains("identity") || !data["identity"].is_object()) return *this;
        fieldData["MiddleName"] = localVault.Encrypt(middleName, itemEncKey, itemMacKey);
        data["identity"]["middleName"] = localVault.Encrypt(middleName, itemEncKey, itemMacKey);
        OPENSSL_cleanse(middleName.data(), middleName.size());
        middleName.clear();
        return *this;
    }

    IdentityItem& IdentityItem::SetPassportNumber(std::string& passportNumber) {
        if (!init) return *this;
        if (!data.contains("identity") || !data["identity"].is_object()) return *this;
        fieldData["PassportNumber"] = localVault.Encrypt(passportNumber, itemEncKey, itemMacKey);
        data["identity"]["passportNumber"] = localVault.Encrypt(passportNumber, itemEncKey, itemMacKey);
        OPENSSL_cleanse(passportNumber.data(), passportNumber.size());
        passportNumber.clear();
        return *this;
    }

    IdentityItem& IdentityItem::SetPhone(std::string& phone) {
        if (!init) return *this;
        if (!data.contains("identity") || !data["identity"].is_object()) return *this;
        fieldData["Phone"] = localVault.Encrypt(phone, itemEncKey, itemMacKey);
        data["identity"]["phone"] = localVault.Encrypt(phone, itemEncKey, itemMacKey);
        OPENSSL_cleanse(phone.data(), phone.size());
        phone.clear();
        return *this;
    }

    IdentityItem& IdentityItem::SetPostalCode(std::string& postalCode) {
        if (!init) return *this;
        if (!data.contains("identity") || !data["identity"].is_object()) return *this;
        fieldData["PostalCode"] = localVault.Encrypt(postalCode, itemEncKey, itemMacKey);
        data["identity"]["postalCode"] = localVault.Encrypt(postalCode, itemEncKey, itemMacKey);
        OPENSSL_cleanse(postalCode.data(), postalCode.size());
        postalCode.clear();
        return *this;
    }

    IdentityItem& IdentityItem::SetSSN(std::string& ssn) {
        if (!init) return *this;
        if (!data.contains("identity") || !data["identity"].is_object()) return *this;
        fieldData["SSN"] = localVault.Encrypt(ssn, itemEncKey, itemMacKey);
        data["identity"]["ssn"] = localVault.Encrypt(ssn, itemEncKey, itemMacKey);
        OPENSSL_cleanse(ssn.data(), ssn.size());
        ssn.clear();
        return *this;
    }

    IdentityItem& IdentityItem::SetState(std::string& state) {
        if (!init) return *this;
        if (!data.contains("identity") || !data["identity"].is_object()) return *this;
        fieldData["State"] = localVault.Encrypt(state, itemEncKey, itemMacKey);
        data["identity"]["state"] = localVault.Encrypt(state, itemEncKey, itemMacKey);
        OPENSSL_cleanse(state.data(), state.size());
        state.clear();
        return *this;
    }

    IdentityItem& IdentityItem::SetTitle(std::string& title) {
        if (!init) return *this;
        if (!data.contains("identity") || !data["identity"].is_object()) return *this;
        fieldData["Title"] = localVault.Encrypt(title, itemEncKey, itemMacKey);
        data["identity"]["title"] = localVault.Encrypt(title, itemEncKey, itemMacKey);
        OPENSSL_cleanse(title.data(), title.size());
        title.clear();
        return *this;
    }

    IdentityItem& IdentityItem::SetUsername(std::string& username) {
        if (!init) return *this;
        if (!data.contains("identity") || !data["identity"].is_object()) return *this;
        fieldData["Username"] = localVault.Encrypt(username, itemEncKey, itemMacKey);
        data["identity"]["username"] = localVault.Encrypt(username, itemEncKey, itemMacKey);
        OPENSSL_cleanse(username.data(), username.size());
        username.clear();
        return *this;
    }

    IdentityItem& IdentityItem::SetNotes(std::string& notes) {
        if (!init) return *this;
        fieldData["Notes"] = localVault.Encrypt(notes, itemEncKey, itemMacKey);
        data["notes"] = localVault.Encrypt(notes, itemEncKey, itemMacKey);
        OPENSSL_cleanse(notes.data(), notes.size());
        notes.clear();
        return *this;
    }

    IdentityItem& IdentityItem::SetFolder(std::string folderUUID) {
        if (!init) return *this;
        data["folderId"] = folderUUID;
        return *this;
    }

    IdentityItem& IdentityItem::RemoveFolder() {
        if (!init) return *this;
        data["folderId"] = nullptr;
        return *this;
    }

    IdentityItem& IdentityItem::AddField(CustomFieldType field, std::string& name, std::string& value) {
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

    IdentityItem& IdentityItem::RemoveField(std::string& name) {
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

    void IdentityItem::Commit() {
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

    void IdentityItem::Delete() {
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

    void IdentityItem::Bin() {
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

    void IdentityItem::Close() {
        if (!init) return;
        OPENSSL_cleanse(itemEncKey.data(), itemEncKey.size());
        itemEncKey.clear();
        OPENSSL_cleanse(itemMacKey.data(), itemMacKey.size());
        itemMacKey.clear();

        localVault.storage.write("vault.json", localVault.vaultData.dump(2));
    }

    IdentityItem& IdentityItem::GetName(std::string& address1) {
        if (!init) return *this;
        if (!data.contains("name")) return *this;
        if (!data["name"].is_string()) return *this;
        address1 = localVault.Decrypt(data["name"], itemEncKey, itemMacKey);
        return *this;
    }

    IdentityItem& IdentityItem::GetAddress1(std::string& address2) {
        if (!init) return *this;
        if (!data["identity"].is_object()) return *this;
        if (!data["identity"].contains("address1")) return *this;
        if (!data["identity"]["address1"].is_string()) return *this;
        address2 = localVault.Decrypt(data["identity"]["address1"], itemEncKey, itemMacKey);
        return *this;
    }

    IdentityItem& IdentityItem::GetAddress2(std::string& address3) {
        if (!init) return *this;
        if (!data["identity"].is_object()) return *this;
        if (!data["identity"].contains("address2")) return *this;
        if (!data["identity"]["address2"].is_string()) return *this;
        address3 = localVault.Decrypt(data["identity"]["address2"], itemEncKey, itemMacKey);
        return *this;
    }

    IdentityItem& IdentityItem::GetAddress3(std::string& city) {
        if (!init) return *this;
        if (!data["identity"].is_object()) return *this;
        if (!data["identity"].contains("address3")) return *this;
        if (!data["identity"]["address3"].is_string()) return *this;
        city = localVault.Decrypt(data["identity"]["address3"], itemEncKey, itemMacKey);
        return *this;
    }

    IdentityItem& IdentityItem::GetCity(std::string& city) {
        if (!init) return *this;
        if (!data["identity"].is_object()) return *this;
        if (!data["identity"].contains("city")) return *this;
        if (!data["identity"]["city"].is_string()) return *this;
        city = localVault.Decrypt(data["identity"]["city"], itemEncKey, itemMacKey);
        return *this;
    }

    IdentityItem& IdentityItem::GetCompany(std::string& company) {
        if (!init) return *this;
        if (!data["identity"].is_object()) return *this;
        if (!data["identity"].contains("company")) return *this;
        if (!data["identity"]["company"].is_string()) return *this;
        company = localVault.Decrypt(data["identity"]["company"], itemEncKey, itemMacKey);
        return *this;
    }

    IdentityItem& IdentityItem::GetCountry(std::string& country) {
        if (!init) return *this;
        if (!data["identity"].is_object()) return *this;
        if (!data["identity"].contains("country")) return *this;
        if (!data["identity"]["country"].is_string()) return *this;
        country = localVault.Decrypt(data["identity"]["country"], itemEncKey, itemMacKey);
        return *this;
    }

    IdentityItem& IdentityItem::GetEmail(std::string& email) {
        if (!init) return *this;
        if (!data["identity"].is_object()) return *this;
        if (!data["identity"].contains("email")) return *this;
        if (!data["identity"]["email"].is_string()) return *this;
        email = localVault.Decrypt(data["identity"]["email"], itemEncKey, itemMacKey);
        return *this;
    }

    IdentityItem& IdentityItem::GetFirstName(std::string& firstName) {
        if (!init) return *this;
        if (!data["identity"].is_object()) return *this;
        if (!data["identity"].contains("firstName")) return *this;
        if (!data["identity"]["firstName"].is_string()) return *this;
        firstName = localVault.Decrypt(data["identity"]["firstName"], itemEncKey, itemMacKey);
        return *this;
    }

    IdentityItem& IdentityItem::GetLastName(std::string& lastName) {
        if (!init) return *this;
        if (!data["identity"].is_object()) return *this;
        if (!data["identity"].contains("lastName")) return *this;
        if (!data["identity"]["lastName"].is_string()) return *this;
        lastName = localVault.Decrypt(data["identity"]["lastName"], itemEncKey, itemMacKey);
        return *this;
    }

    IdentityItem& IdentityItem::GetLicenceNumber(std::string& licenseNumber) {
        if (!init) return *this;
        if (!data["identity"].is_object()) return *this;
        if (!data["identity"].contains("licenseNumber")) return *this;
        if (!data["identity"]["licenseNumber"].is_string()) return *this;
        licenseNumber = localVault.Decrypt(data["identity"]["licenseNumber"], itemEncKey, itemMacKey);
        return *this;
    }

    IdentityItem& IdentityItem::GetMiddleName(std::string& middleName) {
        if (!init) return *this;
        if (!data["identity"].is_object()) return *this;
        if (!data["identity"].contains("middleName")) return *this;
        if (!data["identity"]["middleName"].is_string()) return *this;
        middleName = localVault.Decrypt(data["identity"]["middleName"], itemEncKey, itemMacKey);
        return *this;
    }

    IdentityItem& IdentityItem::GetPassportNumber(std::string& passportNumber) {
        if (!init) return *this;
        if (!data["identity"].is_object()) return *this;
        if (!data["identity"].contains("passportNumber")) return *this;
        if (!data["identity"]["passportNumber"].is_string()) return *this;
        passportNumber = localVault.Decrypt(data["identity"]["passportNumber"], itemEncKey, itemMacKey);
        return *this;
    }

    IdentityItem& IdentityItem::GetPhone(std::string& phone) {
        if (!init) return *this;
        if (!data["identity"].is_object()) return *this;
        if (!data["identity"].contains("phone")) return *this;
        if (!data["identity"]["phone"].is_string()) return *this;
        phone = localVault.Decrypt(data["identity"]["phone"], itemEncKey, itemMacKey);
        return *this;
    }

    IdentityItem& IdentityItem::GetPostalCode(std::string& postalCode) {
        if (!init) return *this;
        if (!data["identity"].is_object()) return *this;
        if (!data["identity"].contains("postalCode")) return *this;
        if (!data["identity"]["postalCode"].is_string()) return *this;
        postalCode = localVault.Decrypt(data["identity"]["postalCode"], itemEncKey, itemMacKey);
        return *this;
    }

    IdentityItem& IdentityItem::GetSSN(std::string& ssn) {
        if (!init) return *this;
        if (!data["identity"].is_object()) return *this;
        if (!data["identity"].contains("ssn")) return *this;
        if (!data["identity"]["ssn"].is_string()) return *this;
        ssn = localVault.Decrypt(data["identity"]["ssn"], itemEncKey, itemMacKey);
        return *this;
    }

    IdentityItem& IdentityItem::GetState(std::string& state) {
        if (!init) return *this;
        if (!data["identity"].is_object()) return *this;
        if (!data["identity"].contains("state")) return *this;
        if (!data["identity"]["state"].is_string()) return *this;
        state = localVault.Decrypt(data["identity"]["state"], itemEncKey, itemMacKey);
        return *this;
    }

    IdentityItem& IdentityItem::GetTitle(std::string& title) {
        if (!init) return *this;
        if (!data["identity"].is_object()) return *this;
        if (!data["identity"].contains("title")) return *this;
        if (!data["identity"]["title"].is_string()) return *this;
        title = localVault.Decrypt(data["identity"]["title"], itemEncKey, itemMacKey);
        return *this;
    }

    IdentityItem& IdentityItem::GetUsername(std::string& username) {
        if (!init) return *this;
        if (!data["identity"].is_object()) return *this;
        if (!data["identity"].contains("username")) return *this;
        if (!data["identity"]["username"].is_string()) return *this;
        username = localVault.Decrypt(data["identity"]["username"], itemEncKey, itemMacKey);
        return *this;
    }

    IdentityItem& IdentityItem::GetNotes(std::string& notes) {
        if (!init) return *this;
        if (!data.contains("notes")) return *this;
        if (!data["notes"].is_string()) return *this;
        notes = localVault.Decrypt(data["notes"], itemEncKey, itemMacKey);
        return *this;
    }

    IdentityItem& IdentityItem::GetFolder(std::string& folder) {
        if (!init) return *this;
        if (!data.contains("folderId")) return *this;
        if (!data["folderId"].is_string()) return *this;
        folder = data["folderId"].is_null() ? "" : data["folderId"].get<std::string>();
        return *this;
    }

    IdentityItem& IdentityItem::GetFields(std::vector<std::tuple<CustomFieldType, std::string, std::string>>& fields) {
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

    IdentityItem& IdentityItem::SetFavorite(bool val) {
        if (!init) return *this;
        data["favorite"] = val;
        return *this;
    }

    IdentityItem& IdentityItem::SetReprompt(bool val) {
        if (!init) return *this;
        if (val) {
            data["reprompt"] = 1;
        } else {
            data["reprompt"] = 0;
        }
        return *this;
    }

    IdentityItem& IdentityItem::GetFavorite(bool& val) {
        if (!init) return *this;
        if (!data.contains("favorite")) return *this;
        if (!data["favorite"].is_boolean()) return *this;
        val = data["favorite"];
        return *this;
    }

    IdentityItem& IdentityItem::GetReprompt(bool& val) {
        if (!init) return *this;
        if (!data["reprompt"].is_number()) return *this;
        if (data["reprompt"].get<int>() == 1) {
            val = true;
        }
        if (data["reprompt"].get<int>() == 0) {
            val = false;
        }
        return *this;
    }

    IdentityItem& IdentityItem::Duplicate(std::string& id) {
        if (!logger) {
            logger = spdlog::stdout_color_mt("ClientWarden::Vault::IdentityItem");
        }
        auto keys = localVault.generateEncMacKeys();
        auto newitemEncKey = keys.first;
        auto newitemMacKey = keys.second;

        /*
         * SECRET DATA
        */
        std::string oldName;
        std::string oldAddress1;
        std::string oldAddress2;
        std::string oldAddress3;
        std::string oldCity;
        std::string oldCompany;
        std::string oldCountry;
        std::string oldEmail;
        std::string oldFirstName;
        std::string oldLastName;
        std::string oldLicenceNumber;
        std::string oldMiddleName;
        std::string oldPassportNumber;
        std::string oldPhone;
        std::string oldPostalCode;
        std::string oldSSN;
        std::string oldState;
        std::string oldTitle;
        std::string oldUsername;
        std::string oldNotes;
        std::vector<std::tuple<CustomFieldType, std::string, std::string>> oldFields;

        bool oldFavorite = false;
        int oldReprompt = 0;

        if (data.contains("name") && data["name"].is_string()) {
            oldName = localVault.Decrypt(data["name"], itemEncKey, itemMacKey);
        }

        if (data.contains("identity") && data["identity"].is_object()) {
            if (data["identity"].contains("address1") && data["identity"]["address1"].is_string()) {
                oldAddress1 = localVault.Decrypt(data["identity"]["address1"], itemEncKey, itemMacKey);
            }
            if (data["identity"].contains("address2") && data["identity"]["address2"].is_string()) {
                oldAddress2 = localVault.Decrypt(data["identity"]["address2"], itemEncKey, itemMacKey);
            }
            if (data["identity"].contains("address3") && data["identity"]["address3"].is_string()) {
                oldAddress3 = localVault.Decrypt(data["identity"]["address3"], itemEncKey, itemMacKey);
            }
            if (data["identity"].contains("city") && data["identity"]["city"].is_string()) {
                oldCity = localVault.Decrypt(data["identity"]["city"], itemEncKey, itemMacKey);
            }
            if (data["identity"].contains("company") && data["identity"]["company"].is_string()) {
                oldCompany = localVault.Decrypt(data["identity"]["company"], itemEncKey, itemMacKey);
            }
            if (data["identity"].contains("country") && data["identity"]["country"].is_string()) {
                oldCountry = localVault.Decrypt(data["identity"]["country"], itemEncKey, itemMacKey);
            }
            if (data["identity"].contains("email") && data["identity"]["email"].is_string()) {
                oldEmail = localVault.Decrypt(data["identity"]["email"], itemEncKey, itemMacKey);
            }
            if (data["identity"].contains("firstName") && data["identity"]["firstName"].is_string()) {
                oldFirstName = localVault.Decrypt(data["identity"]["firstName"], itemEncKey, itemMacKey);
            }
            if (data["identity"].contains("lastName") && data["identity"]["lastName"].is_string()) {
                oldLastName = localVault.Decrypt(data["identity"]["lastName"], itemEncKey, itemMacKey);
            }
            if (data["identity"].contains("licenseNumber") && data["identity"]["licenseNumber"].is_string()) {
                oldLicenceNumber = localVault.Decrypt(data["identity"]["licenseNumber"], itemEncKey, itemMacKey);
            }
            if (data["identity"].contains("middleName") && data["identity"]["middleName"].is_string()) {
                oldMiddleName = localVault.Decrypt(data["identity"]["middleName"], itemEncKey, itemMacKey);
            }
            if (data["identity"].contains("passportNumber") && data["identity"]["passportNumber"].is_string()) {
                oldPassportNumber = localVault.Decrypt(data["identity"]["passportNumber"], itemEncKey, itemMacKey);
            }
            if (data["identity"].contains("phone") && data["identity"]["phone"].is_string()) {
                oldPhone = localVault.Decrypt(data["identity"]["phone"], itemEncKey, itemMacKey);
            }
            if (data["identity"].contains("postalCode") && data["identity"]["postalCode"].is_string()) {
                oldPostalCode = localVault.Decrypt(data["identity"]["postalCode"], itemEncKey, itemMacKey);
            }
            if (data["identity"].contains("ssn") && data["identity"]["ssn"].is_string()) {
                oldSSN = localVault.Decrypt(data["identity"]["ssn"], itemEncKey, itemMacKey);
            }
            if (data["identity"].contains("state") && data["identity"]["state"].is_string()) {
                oldState = localVault.Decrypt(data["identity"]["state"], itemEncKey, itemMacKey);
            }
            if (data["identity"].contains("title") && data["identity"]["title"].is_string()) {
                oldTitle = localVault.Decrypt(data["identity"]["title"], itemEncKey, itemMacKey);
            }
            if (data["identity"].contains("username") && data["identity"]["username"].is_string()) {
                oldUsername = localVault.Decrypt(data["identity"]["username"], itemEncKey, itemMacKey);
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
        newdata["identity"] = nlohmann::json::object();
        newdata["identity"]["address1"] = localVault.Encrypt(oldAddress1, newitemEncKey, newitemMacKey);
        newdata["identity"]["address2"] = localVault.Encrypt(oldAddress2, newitemEncKey, newitemMacKey);
        newdata["identity"]["address3"] = localVault.Encrypt(oldAddress3, newitemEncKey, newitemMacKey);
        newdata["identity"]["city"] = localVault.Encrypt(oldCity, newitemEncKey, newitemMacKey);
        newdata["identity"]["company"] = localVault.Encrypt(oldCompany, newitemEncKey, newitemMacKey);
        newdata["identity"]["country"] = localVault.Encrypt(oldCountry, newitemEncKey, newitemMacKey);
        newdata["identity"]["email"] = localVault.Encrypt(oldEmail, newitemEncKey, newitemMacKey);
        newdata["identity"]["firstName"] = localVault.Encrypt(oldFirstName, newitemEncKey, newitemMacKey);
        newdata["identity"]["lastName"] = localVault.Encrypt(oldLastName, newitemEncKey, newitemMacKey);
        newdata["identity"]["licenseNumber"] = localVault.Encrypt(oldLicenceNumber, newitemEncKey, newitemMacKey);
        newdata["identity"]["middleName"] = localVault.Encrypt(oldMiddleName, newitemEncKey, newitemMacKey);
        newdata["identity"]["passportNumber"] = localVault.Encrypt(oldPassportNumber, newitemEncKey, newitemMacKey);
        newdata["identity"]["phone"] = localVault.Encrypt(oldPhone, newitemEncKey, newitemMacKey);
        newdata["identity"]["postalCode"] = localVault.Encrypt(oldPostalCode, newitemEncKey, newitemMacKey);
        newdata["identity"]["ssn"] = localVault.Encrypt(oldSSN, newitemEncKey, newitemMacKey);
        newdata["identity"]["state"] = localVault.Encrypt(oldState, newitemEncKey, newitemMacKey);
        newdata["identity"]["title"] = localVault.Encrypt(oldTitle, newitemEncKey, newitemMacKey);
        newdata["identity"]["username"] = localVault.Encrypt(oldUsername, newitemEncKey, newitemMacKey);
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
        newdata["type"] = 4;
        newdata["viewPassword"] = true;

        newfieldData["Title"] = localVault.Encrypt(oldTitle, newitemEncKey, newitemMacKey);
        newfieldData["FirstName"] = localVault.Encrypt(oldFirstName, newitemEncKey, newitemMacKey);
        newfieldData["MiddleName"] = localVault.Encrypt(oldMiddleName, newitemEncKey, newitemMacKey);
        newfieldData["LastName"] = localVault.Encrypt(oldLastName, newitemEncKey, newitemMacKey);
        newfieldData["Address1"] = localVault.Encrypt(oldAddress1, newitemEncKey, newitemMacKey);
        newfieldData["Address2"] = localVault.Encrypt(oldAddress2, newitemEncKey, newitemMacKey);
        newfieldData["Address3"] = localVault.Encrypt(oldAddress3, newitemEncKey, newitemMacKey);
        newfieldData["City"] = localVault.Encrypt(oldCity, newitemEncKey, newitemMacKey);
        newfieldData["State"] = localVault.Encrypt(oldState, newitemEncKey, newitemMacKey);
        newfieldData["PostalCode"] = localVault.Encrypt(oldPostalCode, newitemEncKey, newitemMacKey);
        newfieldData["Country"] = localVault.Encrypt(oldCountry, newitemEncKey, newitemMacKey);
        newfieldData["Company"] = localVault.Encrypt(oldCompany, newitemEncKey, newitemMacKey);
        newfieldData["Email"] = localVault.Encrypt(oldEmail, newitemEncKey, newitemMacKey);
        newfieldData["Phone"] = localVault.Encrypt(oldPhone, newitemEncKey, newitemMacKey);
        newfieldData["SSN"] = localVault.Encrypt(oldSSN, newitemEncKey, newitemMacKey);
        newfieldData["Username"] = localVault.Encrypt(oldUsername, newitemEncKey, newitemMacKey);
        newfieldData["PassportNumber"] = localVault.Encrypt(oldPassportNumber, newitemEncKey, newitemMacKey);
        newfieldData["LicenseNumber"] = localVault.Encrypt(oldLicenceNumber, newitemEncKey, newitemMacKey);
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
        OPENSSL_cleanse(oldAddress1.data(), oldAddress1.size());
        oldAddress1.clear();
        OPENSSL_cleanse(oldAddress2.data(), oldAddress2.size());
        oldAddress2.clear();
        OPENSSL_cleanse(oldAddress3.data(), oldAddress3.size());
        oldAddress3.clear();
        OPENSSL_cleanse(oldCity.data(), oldCity.size());
        oldCity.clear();
        OPENSSL_cleanse(oldCompany.data(), oldCompany.size());
        oldCompany.clear();
        OPENSSL_cleanse(oldCountry.data(), oldCountry.size());
        oldCountry.clear();
        OPENSSL_cleanse(oldEmail.data(), oldEmail.size());
        oldEmail.clear();
        OPENSSL_cleanse(oldFirstName.data(), oldFirstName.size());
        oldFirstName.clear();
        OPENSSL_cleanse(oldLastName.data(), oldLastName.size());
        oldLastName.clear();
        OPENSSL_cleanse(oldLicenceNumber.data(), oldLicenceNumber.size());
        oldLicenceNumber.clear();
        OPENSSL_cleanse(oldMiddleName.data(), oldMiddleName.size());
        oldMiddleName.clear();
        OPENSSL_cleanse(oldPassportNumber.data(), oldPassportNumber.size());
        oldPassportNumber.clear();
        OPENSSL_cleanse(oldPhone.data(), oldPhone.size());
        oldPhone.clear();
        OPENSSL_cleanse(oldPostalCode.data(), oldPostalCode.size());
        oldPostalCode.clear();
        OPENSSL_cleanse(oldSSN.data(), oldSSN.size());
        oldSSN.clear();
        OPENSSL_cleanse(oldState.data(), oldState.size());
        oldState.clear();
        OPENSSL_cleanse(oldTitle.data(), oldTitle.size());
        oldTitle.clear();
        OPENSSL_cleanse(oldUsername.data(), oldUsername.size());
        oldUsername.clear();
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
}