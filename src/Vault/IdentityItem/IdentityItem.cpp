#include "IdentityItem.h"
#include "Vault.h"

namespace ClientWarden {
    IdentityItem::IdentityItem(Vault& vault, std::string uuid) : GenericItemImpl<IdentityItem>(vault, uuid) {
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

    IdentityItem::IdentityItem(Vault& vault) : GenericItemImpl<IdentityItem>(vault) {
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
        fieldData["Name"] = localVault.crypto.Encrypt("", itemEncKey, itemMacKey);
        fieldData["Notes"] = nullptr;
        fieldData["Fields"] = nlohmann::json::array();

        init = true;
    }

    IdentityItem* IdentityItem::SetAddress1(std::string& address1) {
        if (!init) return this;
        if (!data.contains("identity") || !data["identity"].is_object()) return this;
        fieldData["Address1"] = localVault.crypto.Encrypt(address1, itemEncKey, itemMacKey);
        data["identity"]["address1"] = localVault.crypto.Encrypt(address1, itemEncKey, itemMacKey);
        OPENSSL_cleanse(address1.data(), address1.size());
        address1.clear();
        return this;
    }

    IdentityItem* IdentityItem::SetAddress2(std::string& address2) {
        if (!init) return this;
        if (!data.contains("identity") || !data["identity"].is_object()) return this;
        fieldData["Address2"] = localVault.crypto.Encrypt(address2, itemEncKey, itemMacKey);
        data["identity"]["address2"] = localVault.crypto.Encrypt(address2, itemEncKey, itemMacKey);
        OPENSSL_cleanse(address2.data(), address2.size());
        address2.clear();
        return this;
    }

    IdentityItem* IdentityItem::SetAddress3(std::string& address3) {
        if (!init) return this;
        if (!data.contains("identity") || !data["identity"].is_object()) return this;
        fieldData["Address3"] = localVault.crypto.Encrypt(address3, itemEncKey, itemMacKey);
        data["identity"]["address3"] = localVault.crypto.Encrypt(address3, itemEncKey, itemMacKey);
        OPENSSL_cleanse(address3.data(), address3.size());
        address3.clear();
        return this;
    }

    IdentityItem* IdentityItem::SetCity(std::string& city) {
        if (!init) return this;
        if (!data.contains("identity") || !data["identity"].is_object()) return this;
        fieldData["City"] = localVault.crypto.Encrypt(city, itemEncKey, itemMacKey);
        data["identity"]["city"] = localVault.crypto.Encrypt(city, itemEncKey, itemMacKey);
        OPENSSL_cleanse(city.data(), city.size());
        city.clear();
        return this;
    }

    IdentityItem* IdentityItem::SetCompany(std::string& company) {
        if (!init) return this;
        if (!data.contains("identity") || !data["identity"].is_object()) return this;
        fieldData["Company"] = localVault.crypto.Encrypt(company, itemEncKey, itemMacKey);
        data["identity"]["company"] = localVault.crypto.Encrypt(company, itemEncKey, itemMacKey);
        OPENSSL_cleanse(company.data(), company.size());
        company.clear();
        return this;
    }

    IdentityItem* IdentityItem::SetCountry(std::string& country) {
        if (!init) return this;
        if (!data.contains("identity") || !data["identity"].is_object()) return this;
        fieldData["Country"] = localVault.crypto.Encrypt(country, itemEncKey, itemMacKey);
        data["identity"]["country"] = localVault.crypto.Encrypt(country, itemEncKey, itemMacKey);
        OPENSSL_cleanse(country.data(), country.size());
        country.clear();
        return this;
    }

    IdentityItem* IdentityItem::SetEmail(std::string& email) {
        if (!init) return this;
        if (!data.contains("identity") || !data["identity"].is_object()) return this;
        fieldData["Email"] = localVault.crypto.Encrypt(email, itemEncKey, itemMacKey);
        data["identity"]["email"] = localVault.crypto.Encrypt(email, itemEncKey, itemMacKey);
        OPENSSL_cleanse(email.data(), email.size());
        email.clear();
        return this;
    }

    IdentityItem* IdentityItem::SetFirstName(std::string& firstName) {
        if (!init) return this;
        if (!data.contains("identity") || !data["identity"].is_object()) return this;
        fieldData["FirstName"] = localVault.crypto.Encrypt(firstName, itemEncKey, itemMacKey);
        data["identity"]["firstName"] = localVault.crypto.Encrypt(firstName, itemEncKey, itemMacKey);
        OPENSSL_cleanse(firstName.data(), firstName.size());
        firstName.clear();
        return this;
    }

    IdentityItem* IdentityItem::SetLastName(std::string& lastName) {
        if (!init) return this;
        if (!data.contains("identity") || !data["identity"].is_object()) return this;
        fieldData["LastName"] = localVault.crypto.Encrypt(lastName, itemEncKey, itemMacKey);
        data["identity"]["lastName"] = localVault.crypto.Encrypt(lastName, itemEncKey, itemMacKey);
        OPENSSL_cleanse(lastName.data(), lastName.size());
        lastName.clear();
        return this;
    }

    IdentityItem* IdentityItem::SetLicenceNumber(std::string& licenceNumber) {
        if (!init) return this;
        if (!data.contains("identity") || !data["identity"].is_object()) return this;
        fieldData["LicenseNumber"] = localVault.crypto.Encrypt(licenceNumber, itemEncKey, itemMacKey);
        data["identity"]["licenseNumber"] = localVault.crypto.Encrypt(licenceNumber, itemEncKey, itemMacKey);
        OPENSSL_cleanse(licenceNumber.data(), licenceNumber.size());
        licenceNumber.clear();
        return this;
    }

    IdentityItem* IdentityItem::SetMiddleName(std::string& middleName) {
        if (!init) return this;
        if (!data.contains("identity") || !data["identity"].is_object()) return this;
        fieldData["MiddleName"] = localVault.crypto.Encrypt(middleName, itemEncKey, itemMacKey);
        data["identity"]["middleName"] = localVault.crypto.Encrypt(middleName, itemEncKey, itemMacKey);
        OPENSSL_cleanse(middleName.data(), middleName.size());
        middleName.clear();
        return this;
    }

    IdentityItem* IdentityItem::SetPassportNumber(std::string& passportNumber) {
        if (!init) return this;
        if (!data.contains("identity") || !data["identity"].is_object()) return this;
        fieldData["PassportNumber"] = localVault.crypto.Encrypt(passportNumber, itemEncKey, itemMacKey);
        data["identity"]["passportNumber"] = localVault.crypto.Encrypt(passportNumber, itemEncKey, itemMacKey);
        OPENSSL_cleanse(passportNumber.data(), passportNumber.size());
        passportNumber.clear();
        return this;
    }

    IdentityItem* IdentityItem::SetPhone(std::string& phone) {
        if (!init) return this;
        if (!data.contains("identity") || !data["identity"].is_object()) return this;
        fieldData["Phone"] = localVault.crypto.Encrypt(phone, itemEncKey, itemMacKey);
        data["identity"]["phone"] = localVault.crypto.Encrypt(phone, itemEncKey, itemMacKey);
        OPENSSL_cleanse(phone.data(), phone.size());
        phone.clear();
        return this;
    }

    IdentityItem* IdentityItem::SetPostalCode(std::string& postalCode) {
        if (!init) return this;
        if (!data.contains("identity") || !data["identity"].is_object()) return this;
        fieldData["PostalCode"] = localVault.crypto.Encrypt(postalCode, itemEncKey, itemMacKey);
        data["identity"]["postalCode"] = localVault.crypto.Encrypt(postalCode, itemEncKey, itemMacKey);
        OPENSSL_cleanse(postalCode.data(), postalCode.size());
        postalCode.clear();
        return this;
    }

    IdentityItem* IdentityItem::SetSSN(std::string& ssn) {
        if (!init) return this;
        if (!data.contains("identity") || !data["identity"].is_object()) return this;
        fieldData["SSN"] = localVault.crypto.Encrypt(ssn, itemEncKey, itemMacKey);
        data["identity"]["ssn"] = localVault.crypto.Encrypt(ssn, itemEncKey, itemMacKey);
        OPENSSL_cleanse(ssn.data(), ssn.size());
        ssn.clear();
        return this;
    }

    IdentityItem* IdentityItem::SetState(std::string& state) {
        if (!init) return this;
        if (!data.contains("identity") || !data["identity"].is_object()) return this;
        fieldData["State"] = localVault.crypto.Encrypt(state, itemEncKey, itemMacKey);
        data["identity"]["state"] = localVault.crypto.Encrypt(state, itemEncKey, itemMacKey);
        OPENSSL_cleanse(state.data(), state.size());
        state.clear();
        return this;
    }

    IdentityItem* IdentityItem::SetTitle(std::string& title) {
        if (!init) return this;
        if (!data.contains("identity") || !data["identity"].is_object()) return this;
        fieldData["Title"] = localVault.crypto.Encrypt(title, itemEncKey, itemMacKey);
        data["identity"]["title"] = localVault.crypto.Encrypt(title, itemEncKey, itemMacKey);
        OPENSSL_cleanse(title.data(), title.size());
        title.clear();
        return this;
    }

    IdentityItem* IdentityItem::SetUsername(std::string& username) {
        if (!init) return this;
        if (!data.contains("identity") || !data["identity"].is_object()) return this;
        fieldData["Username"] = localVault.crypto.Encrypt(username, itemEncKey, itemMacKey);
        data["identity"]["username"] = localVault.crypto.Encrypt(username, itemEncKey, itemMacKey);
        OPENSSL_cleanse(username.data(), username.size());
        username.clear();
        return this;
    }

    IdentityItem* IdentityItem::GetAddress1(std::string& address1) {
        if (!init) return this;
        if (!data["identity"].is_object()) return this;
        if (!data["identity"].contains("address1")) return this;
        if (!data["identity"]["address1"].is_string()) return this;
        address1 = localVault.crypto.DecryptAsStr(data["identity"]["address1"], itemEncKey, itemMacKey);
        return this;
    }

    IdentityItem* IdentityItem::GetAddress2(std::string& address2) {
        if (!init) return this;
        if (!data["identity"].is_object()) return this;
        if (!data["identity"].contains("address2")) return this;
        if (!data["identity"]["address2"].is_string()) return this;
        address2 = localVault.crypto.DecryptAsStr(data["identity"]["address2"], itemEncKey, itemMacKey);
        return this;
    }

    IdentityItem* IdentityItem::GetAddress3(std::string& address3) {
        if (!init) return this;
        if (!data["identity"].is_object()) return this;
        if (!data["identity"].contains("address3")) return this;
        if (!data["identity"]["address3"].is_string()) return this;
        address3 = localVault.crypto.DecryptAsStr(data["identity"]["address3"], itemEncKey, itemMacKey);
        return this;
    }

    IdentityItem* IdentityItem::GetCity(std::string& city) {
        if (!init) return this;
        if (!data["identity"].is_object()) return this;
        if (!data["identity"].contains("city")) return this;
        if (!data["identity"]["city"].is_string()) return this;
        city = localVault.crypto.DecryptAsStr(data["identity"]["city"], itemEncKey, itemMacKey);
        return this;
    }

    IdentityItem* IdentityItem::GetCompany(std::string& company) {
        if (!init) return this;
        if (!data["identity"].is_object()) return this;
        if (!data["identity"].contains("company")) return this;
        if (!data["identity"]["company"].is_string()) return this;
        company = localVault.crypto.DecryptAsStr(data["identity"]["company"], itemEncKey, itemMacKey);
        return this;
    }

    IdentityItem* IdentityItem::GetCountry(std::string& country) {
        if (!init) return this;
        if (!data["identity"].is_object()) return this;
        if (!data["identity"].contains("country")) return this;
        if (!data["identity"]["country"].is_string()) return this;
        country = localVault.crypto.DecryptAsStr(data["identity"]["country"], itemEncKey, itemMacKey);
        return this;
    }

    IdentityItem* IdentityItem::GetEmail(std::string& email) {
        if (!init) return this;
        if (!data["identity"].is_object()) return this;
        if (!data["identity"].contains("email")) return this;
        if (!data["identity"]["email"].is_string()) return this;
        email = localVault.crypto.DecryptAsStr(data["identity"]["email"], itemEncKey, itemMacKey);
        return this;
    }

    IdentityItem* IdentityItem::GetFirstName(std::string& firstName) {
        if (!init) return this;
        if (!data["identity"].is_object()) return this;
        if (!data["identity"].contains("firstName")) return this;
        if (!data["identity"]["firstName"].is_string()) return this;
        firstName = localVault.crypto.DecryptAsStr(data["identity"]["firstName"], itemEncKey, itemMacKey);
        return this;
    }

    IdentityItem* IdentityItem::GetLastName(std::string& lastName) {
        if (!init) return this;
        if (!data["identity"].is_object()) return this;
        if (!data["identity"].contains("lastName")) return this;
        if (!data["identity"]["lastName"].is_string()) return this;
        lastName = localVault.crypto.DecryptAsStr(data["identity"]["lastName"], itemEncKey, itemMacKey);
        return this;
    }

    IdentityItem* IdentityItem::GetLicenceNumber(std::string& licenseNumber) {
        if (!init) return this;
        if (!data["identity"].is_object()) return this;
        if (!data["identity"].contains("licenseNumber")) return this;
        if (!data["identity"]["licenseNumber"].is_string()) return this;
        licenseNumber = localVault.crypto.DecryptAsStr(data["identity"]["licenseNumber"], itemEncKey, itemMacKey);
        return this;
    }

    IdentityItem* IdentityItem::GetMiddleName(std::string& middleName) {
        if (!init) return this;
        if (!data["identity"].is_object()) return this;
        if (!data["identity"].contains("middleName")) return this;
        if (!data["identity"]["middleName"].is_string()) return this;
        middleName = localVault.crypto.DecryptAsStr(data["identity"]["middleName"], itemEncKey, itemMacKey);
        return this;
    }

    IdentityItem* IdentityItem::GetPassportNumber(std::string& passportNumber) {
        if (!init) return this;
        if (!data["identity"].is_object()) return this;
        if (!data["identity"].contains("passportNumber")) return this;
        if (!data["identity"]["passportNumber"].is_string()) return this;
        passportNumber = localVault.crypto.DecryptAsStr(data["identity"]["passportNumber"], itemEncKey, itemMacKey);
        return this;
    }

    IdentityItem* IdentityItem::GetPhone(std::string& phone) {
        if (!init) return this;
        if (!data["identity"].is_object()) return this;
        if (!data["identity"].contains("phone")) return this;
        if (!data["identity"]["phone"].is_string()) return this;
        phone = localVault.crypto.DecryptAsStr(data["identity"]["phone"], itemEncKey, itemMacKey);
        return this;
    }

    IdentityItem* IdentityItem::GetPostalCode(std::string& postalCode) {
        if (!init) return this;
        if (!data["identity"].is_object()) return this;
        if (!data["identity"].contains("postalCode")) return this;
        if (!data["identity"]["postalCode"].is_string()) return this;
        postalCode = localVault.crypto.DecryptAsStr(data["identity"]["postalCode"], itemEncKey, itemMacKey);
        return this;
    }

    IdentityItem* IdentityItem::GetSSN(std::string& ssn) {
        if (!init) return this;
        if (!data["identity"].is_object()) return this;
        if (!data["identity"].contains("ssn")) return this;
        if (!data["identity"]["ssn"].is_string()) return this;
        ssn = localVault.crypto.DecryptAsStr(data["identity"]["ssn"], itemEncKey, itemMacKey);
        return this;
    }

    IdentityItem* IdentityItem::GetState(std::string& state) {
        if (!init) return this;
        if (!data["identity"].is_object()) return this;
        if (!data["identity"].contains("state")) return this;
        if (!data["identity"]["state"].is_string()) return this;
        state = localVault.crypto.DecryptAsStr(data["identity"]["state"], itemEncKey, itemMacKey);
        return this;
    }

    IdentityItem* IdentityItem::GetTitle(std::string& title) {
        if (!init) return this;
        if (!data["identity"].is_object()) return this;
        if (!data["identity"].contains("title")) return this;
        if (!data["identity"]["title"].is_string()) return this;
        title = localVault.crypto.DecryptAsStr(data["identity"]["title"], itemEncKey, itemMacKey);
        return this;
    }

    IdentityItem* IdentityItem::GetUsername(std::string& username) {
        if (!init) return this;
        if (!data["identity"].is_object()) return this;
        if (!data["identity"].contains("username")) return this;
        if (!data["identity"]["username"].is_string()) return this;
        username = localVault.crypto.DecryptAsStr(data["identity"]["username"], itemEncKey, itemMacKey);
        return this;
    }

    IdentityItem* IdentityItem::Duplicate(std::string& id) {
        auto keys = localVault.crypto.generateEncMacKeys();
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
            oldName = localVault.crypto.DecryptAsStr(data["name"], itemEncKey, itemMacKey);
        }

        if (data.contains("identity") && data["identity"].is_object()) {
            if (data["identity"].contains("address1") && data["identity"]["address1"].is_string()) {
                oldAddress1 = localVault.crypto.DecryptAsStr(data["identity"]["address1"], itemEncKey, itemMacKey);
            }
            if (data["identity"].contains("address2") && data["identity"]["address2"].is_string()) {
                oldAddress2 = localVault.crypto.DecryptAsStr(data["identity"]["address2"], itemEncKey, itemMacKey);
            }
            if (data["identity"].contains("address3") && data["identity"]["address3"].is_string()) {
                oldAddress3 = localVault.crypto.DecryptAsStr(data["identity"]["address3"], itemEncKey, itemMacKey);
            }
            if (data["identity"].contains("city") && data["identity"]["city"].is_string()) {
                oldCity = localVault.crypto.DecryptAsStr(data["identity"]["city"], itemEncKey, itemMacKey);
            }
            if (data["identity"].contains("company") && data["identity"]["company"].is_string()) {
                oldCompany = localVault.crypto.DecryptAsStr(data["identity"]["company"], itemEncKey, itemMacKey);
            }
            if (data["identity"].contains("country") && data["identity"]["country"].is_string()) {
                oldCountry = localVault.crypto.DecryptAsStr(data["identity"]["country"], itemEncKey, itemMacKey);
            }
            if (data["identity"].contains("email") && data["identity"]["email"].is_string()) {
                oldEmail = localVault.crypto.DecryptAsStr(data["identity"]["email"], itemEncKey, itemMacKey);
            }
            if (data["identity"].contains("firstName") && data["identity"]["firstName"].is_string()) {
                oldFirstName = localVault.crypto.DecryptAsStr(data["identity"]["firstName"], itemEncKey, itemMacKey);
            }
            if (data["identity"].contains("lastName") && data["identity"]["lastName"].is_string()) {
                oldLastName = localVault.crypto.DecryptAsStr(data["identity"]["lastName"], itemEncKey, itemMacKey);
            }
            if (data["identity"].contains("licenseNumber") && data["identity"]["licenseNumber"].is_string()) {
                oldLicenceNumber = localVault.crypto.DecryptAsStr(data["identity"]["licenseNumber"], itemEncKey, itemMacKey);
            }
            if (data["identity"].contains("middleName") && data["identity"]["middleName"].is_string()) {
                oldMiddleName = localVault.crypto.DecryptAsStr(data["identity"]["middleName"], itemEncKey, itemMacKey);
            }
            if (data["identity"].contains("passportNumber") && data["identity"]["passportNumber"].is_string()) {
                oldPassportNumber = localVault.crypto.DecryptAsStr(data["identity"]["passportNumber"], itemEncKey, itemMacKey);
            }
            if (data["identity"].contains("phone") && data["identity"]["phone"].is_string()) {
                oldPhone = localVault.crypto.DecryptAsStr(data["identity"]["phone"], itemEncKey, itemMacKey);
            }
            if (data["identity"].contains("postalCode") && data["identity"]["postalCode"].is_string()) {
                oldPostalCode = localVault.crypto.DecryptAsStr(data["identity"]["postalCode"], itemEncKey, itemMacKey);
            }
            if (data["identity"].contains("ssn") && data["identity"]["ssn"].is_string()) {
                oldSSN = localVault.crypto.DecryptAsStr(data["identity"]["ssn"], itemEncKey, itemMacKey);
            }
            if (data["identity"].contains("state") && data["identity"]["state"].is_string()) {
                oldState = localVault.crypto.DecryptAsStr(data["identity"]["state"], itemEncKey, itemMacKey);
            }
            if (data["identity"].contains("title") && data["identity"]["title"].is_string()) {
                oldTitle = localVault.crypto.DecryptAsStr(data["identity"]["title"], itemEncKey, itemMacKey);
            }
            if (data["identity"].contains("username") && data["identity"]["username"].is_string()) {
                oldUsername = localVault.crypto.DecryptAsStr(data["identity"]["username"], itemEncKey, itemMacKey);
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
        newdata["identity"] = nlohmann::json::object();
        newdata["identity"]["address1"] = localVault.crypto.Encrypt(oldAddress1, newitemEncKey, newitemMacKey);
        newdata["identity"]["address2"] = localVault.crypto.Encrypt(oldAddress2, newitemEncKey, newitemMacKey);
        newdata["identity"]["address3"] = localVault.crypto.Encrypt(oldAddress3, newitemEncKey, newitemMacKey);
        newdata["identity"]["city"] = localVault.crypto.Encrypt(oldCity, newitemEncKey, newitemMacKey);
        newdata["identity"]["company"] = localVault.crypto.Encrypt(oldCompany, newitemEncKey, newitemMacKey);
        newdata["identity"]["country"] = localVault.crypto.Encrypt(oldCountry, newitemEncKey, newitemMacKey);
        newdata["identity"]["email"] = localVault.crypto.Encrypt(oldEmail, newitemEncKey, newitemMacKey);
        newdata["identity"]["firstName"] = localVault.crypto.Encrypt(oldFirstName, newitemEncKey, newitemMacKey);
        newdata["identity"]["lastName"] = localVault.crypto.Encrypt(oldLastName, newitemEncKey, newitemMacKey);
        newdata["identity"]["licenseNumber"] = localVault.crypto.Encrypt(oldLicenceNumber, newitemEncKey, newitemMacKey);
        newdata["identity"]["middleName"] = localVault.crypto.Encrypt(oldMiddleName, newitemEncKey, newitemMacKey);
        newdata["identity"]["passportNumber"] = localVault.crypto.Encrypt(oldPassportNumber, newitemEncKey, newitemMacKey);
        newdata["identity"]["phone"] = localVault.crypto.Encrypt(oldPhone, newitemEncKey, newitemMacKey);
        newdata["identity"]["postalCode"] = localVault.crypto.Encrypt(oldPostalCode, newitemEncKey, newitemMacKey);
        newdata["identity"]["ssn"] = localVault.crypto.Encrypt(oldSSN, newitemEncKey, newitemMacKey);
        newdata["identity"]["state"] = localVault.crypto.Encrypt(oldState, newitemEncKey, newitemMacKey);
        newdata["identity"]["title"] = localVault.crypto.Encrypt(oldTitle, newitemEncKey, newitemMacKey);
        newdata["identity"]["username"] = localVault.crypto.Encrypt(oldUsername, newitemEncKey, newitemMacKey);
        Botan::secure_vector<uint8_t> mainKey(newitemEncKey.begin(), newitemEncKey.end());
        mainKey.insert(mainKey.end(), newitemMacKey.begin(), newitemMacKey.end());
        newdata["key"] = localVault.crypto.Encrypt(mainKey, localVault.encKey, localVault.macKey);
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
        newdata["sshKey"] = nullptr;
        newdata["type"] = 4;
        newdata["viewPassword"] = true;

        newfieldData["Title"] = localVault.crypto.Encrypt(oldTitle, newitemEncKey, newitemMacKey);
        newfieldData["FirstName"] = localVault.crypto.Encrypt(oldFirstName, newitemEncKey, newitemMacKey);
        newfieldData["MiddleName"] = localVault.crypto.Encrypt(oldMiddleName, newitemEncKey, newitemMacKey);
        newfieldData["LastName"] = localVault.crypto.Encrypt(oldLastName, newitemEncKey, newitemMacKey);
        newfieldData["Address1"] = localVault.crypto.Encrypt(oldAddress1, newitemEncKey, newitemMacKey);
        newfieldData["Address2"] = localVault.crypto.Encrypt(oldAddress2, newitemEncKey, newitemMacKey);
        newfieldData["Address3"] = localVault.crypto.Encrypt(oldAddress3, newitemEncKey, newitemMacKey);
        newfieldData["City"] = localVault.crypto.Encrypt(oldCity, newitemEncKey, newitemMacKey);
        newfieldData["State"] = localVault.crypto.Encrypt(oldState, newitemEncKey, newitemMacKey);
        newfieldData["PostalCode"] = localVault.crypto.Encrypt(oldPostalCode, newitemEncKey, newitemMacKey);
        newfieldData["Country"] = localVault.crypto.Encrypt(oldCountry, newitemEncKey, newitemMacKey);
        newfieldData["Company"] = localVault.crypto.Encrypt(oldCompany, newitemEncKey, newitemMacKey);
        newfieldData["Email"] = localVault.crypto.Encrypt(oldEmail, newitemEncKey, newitemMacKey);
        newfieldData["Phone"] = localVault.crypto.Encrypt(oldPhone, newitemEncKey, newitemMacKey);
        newfieldData["SSN"] = localVault.crypto.Encrypt(oldSSN, newitemEncKey, newitemMacKey);
        newfieldData["Username"] = localVault.crypto.Encrypt(oldUsername, newitemEncKey, newitemMacKey);
        newfieldData["PassportNumber"] = localVault.crypto.Encrypt(oldPassportNumber, newitemEncKey, newitemMacKey);
        newfieldData["LicenseNumber"] = localVault.crypto.Encrypt(oldLicenceNumber, newitemEncKey, newitemMacKey);
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
        std::optional<nlohmann::json> result = localVault.NewItem(newdata);
        if (!result.has_value()) {
            logger->warn("Failed to add New Item Online");
            newdata["createdOffline"] = true;
        } else {
            if (result.contains("id") && result["id"].is_string()) {
                newdata["id"] = result["id"];
            }
        }
        (*localVault.session.vaultData)["ciphers"].push_back(newdata);
        localVault.storage.write("vault.json", localVault.session.vaultData->dump(2));

        id = newdata["id"];

        return this;
    }

    IdentityItem* IdentityItem::GetType(CipherType& val) {
        val = CipherType::Identity;
        return this;
    }
}