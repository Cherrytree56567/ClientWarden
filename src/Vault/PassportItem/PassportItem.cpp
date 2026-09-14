#include "PassportItem.h"
#include "Vault.h"

namespace ClientWarden {
    PassportItem::PassportItem(Vault& vault, std::string uuid) : GenericItemImpl<PassportItem>(vault, uuid) {
        init = false;
        if (data.contains("type") && data["type"].is_number()) {
            if (data["type"].get<int>() == 8) {
                init = true;
            }
        }
        if (!data.contains("passport")) {
            init = false;
        }
    }

    PassportItem::PassportItem(Vault& vault) : GenericItemImpl<PassportItem>(vault) {
        auto keys = localVault.crypto.generateEncMacKeys();
        itemEncKey = keys.first;
        itemMacKey = keys.second;

        data["archivedDate"] = nullptr;
        data["attachments"] = nullptr;
        data["card"] = nullptr;
        data["collectionIds"] = nlohmann::json::array();
        data["creationDate"] = getBitwardenTime();
        if (!localVault.features.checkAbove26_6_0()) {
            data["data"] = "";
        }
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
        data["login"] = nullptr;
        data["bankAccount"] = nullptr;
        data["passport"] = nlohmann::json::object();
        data["passport"]["surname"] = localVault.crypto.Encrypt("", itemEncKey, itemMacKey);
        data["passport"]["givenName"] = localVault.crypto.Encrypt("", itemEncKey, itemMacKey);
        data["passport"]["dateOfBirth"] = localVault.crypto.Encrypt("", itemEncKey, itemMacKey);
        data["passport"]["sex"] = localVault.crypto.Encrypt("", itemEncKey, itemMacKey);
        data["passport"]["birthPlace"] = localVault.crypto.Encrypt("", itemEncKey, itemMacKey);
        data["passport"]["nationality"] = localVault.crypto.Encrypt("", itemEncKey, itemMacKey);
        data["passport"]["issuingCountry"] = localVault.crypto.Encrypt("", itemEncKey, itemMacKey);
        data["passport"]["passportNumber"] = localVault.crypto.Encrypt("", itemEncKey, itemMacKey);
        data["passport"]["passportType"] = localVault.crypto.Encrypt("", itemEncKey, itemMacKey);
        data["passport"]["nationalIdentificationNumber"] = localVault.crypto.Encrypt("", itemEncKey, itemMacKey);
        data["passport"]["issuingAuthority"] = localVault.crypto.Encrypt("", itemEncKey, itemMacKey);
        data["passport"]["issueDate"] = localVault.crypto.Encrypt("", itemEncKey, itemMacKey);
        data["passport"]["expirationDate"] = localVault.crypto.Encrypt("", itemEncKey, itemMacKey);
        data["driversLicense"] = nullptr;
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
        data["type"] = 8;
        data["viewPassword"] = true;

        fieldData["Fields"] = nlohmann::json::array();
        fieldData["Name"] = localVault.crypto.Encrypt("", itemEncKey, itemMacKey);
        fieldData["Notes"] = nullptr;

        init = true;
    }

    PassportItem* PassportItem::Duplicate(std::string& id) {
        auto keys = localVault.crypto.generateEncMacKeys();
        auto newitemEncKey = keys.first;
        auto newitemMacKey = keys.second;

        /*
         * SECRET DATA
        */
        std::string oldName;
        std::string oldSurname;
        std::string oldGivenName;
        std::string oldDateOfBirth;
        std::string oldSex;
        std::string oldBirthPlace;
        std::string oldNationality;
        std::string oldIssuingCountry;
        std::string oldPassportNumber;
        std::string oldPassportType;
        std::string oldNationalIdentificationNumber;
        std::string oldIssuingAuthority;
        std::string oldIssueDate;
        std::string oldExpirationDate;
        std::string oldNotes;
        std::vector<std::tuple<CustomFieldType, std::string, std::string>> oldFields;

        bool oldFavorite = false;
        int oldReprompt = 0;

        if (data.contains("name") && data["name"].is_string()) {
            oldName = localVault.crypto.DecryptAsStr(data["name"], itemEncKey, itemMacKey);
        }

        if (data.contains("passport") && data["passport"].is_object()) {
            if (data["passport"].contains("surname") && data["passport"]["surname"].is_string()) {
                oldSurname = localVault.crypto.DecryptAsStr(data["passport"]["surname"], itemEncKey, itemMacKey);
            }
            if (data["passport"].contains("givenName") && data["passport"]["givenName"].is_string()) {
                oldGivenName = localVault.crypto.DecryptAsStr(data["passport"]["givenName"], itemEncKey, itemMacKey);
            }
            if (data["passport"].contains("dateOfBirth") && data["passport"]["dateOfBirth"].is_string()) {
                oldDateOfBirth = localVault.crypto.DecryptAsStr(data["passport"]["dateOfBirth"], itemEncKey, itemMacKey);
            }
            if (data["passport"].contains("sex") && data["passport"]["sex"].is_string()) {
                oldSex = localVault.crypto.DecryptAsStr(data["passport"]["sex"], itemEncKey, itemMacKey);
            }
            if (data["passport"].contains("birthPlace") && data["passport"]["birthPlace"].is_string()) {
                oldBirthPlace = localVault.crypto.DecryptAsStr(data["passport"]["birthPlace"], itemEncKey, itemMacKey);
            }
            if (data["passport"].contains("nationality") && data["passport"]["nationality"].is_string()) {
                oldNationality = localVault.crypto.DecryptAsStr(data["passport"]["nationality"], itemEncKey, itemMacKey);
            }
            if (data["passport"].contains("issuingCountry") && data["passport"]["issuingCountry"].is_string()) {
                oldIssuingCountry = localVault.crypto.DecryptAsStr(data["passport"]["issuingCountry"], itemEncKey, itemMacKey);
            }
            if (data["passport"].contains("passportNumber") && data["passport"]["passportNumber"].is_string()) {
                oldPassportNumber = localVault.crypto.DecryptAsStr(data["passport"]["passportNumber"], itemEncKey, itemMacKey);
            }
            if (data["passport"].contains("passportType") && data["passport"]["passportType"].is_string()) {
                oldPassportType = localVault.crypto.DecryptAsStr(data["passport"]["passportType"], itemEncKey, itemMacKey);
            }
            if (data["passport"].contains("nationalIdentificationNumber") && data["passport"]["nationalIdentificationNumber"].is_string()) {
                oldNationalIdentificationNumber = localVault.crypto.DecryptAsStr(data["passport"]["nationalIdentificationNumber"], itemEncKey, itemMacKey);
            }
            if (data["passport"].contains("issuingAuthority") && data["passport"]["issuingAuthority"].is_string()) {
                oldIssuingAuthority = localVault.crypto.DecryptAsStr(data["passport"]["issuingAuthority"], itemEncKey, itemMacKey);
            }
            if (data["passport"].contains("issueDate") && data["passport"]["issueDate"].is_string()) {
                oldIssueDate = localVault.crypto.DecryptAsStr(data["passport"]["issueDate"], itemEncKey, itemMacKey);
            }
            if (data["passport"].contains("expirationDate") && data["passport"]["expirationDate"].is_string()) {
                oldExpirationDate = localVault.crypto.DecryptAsStr(data["passport"]["expirationDate"], itemEncKey, itemMacKey);
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
        if (!localVault.features.checkAbove26_6_0()) {
            newdata["data"] = "";
        }
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
        newdata["driversLicense"] = nullptr;
        newdata["login"] = nullptr;
        newdata["bankAccount"] = nullptr;
        newdata["passport"] = nlohmann::json::object();
        newdata["passport"]["surname"] = localVault.crypto.Encrypt(oldSurname, newitemEncKey, newitemMacKey);
        newdata["passport"]["givenName"] = localVault.crypto.Encrypt(oldGivenName, newitemEncKey, newitemMacKey);
        newdata["passport"]["dateOfBirth"] = localVault.crypto.Encrypt(oldDateOfBirth, newitemEncKey, newitemMacKey);
        newdata["passport"]["sex"] = localVault.crypto.Encrypt(oldSex, newitemEncKey, newitemMacKey);
        newdata["passport"]["birthPlace"] = localVault.crypto.Encrypt(oldBirthPlace, newitemEncKey, newitemMacKey);
        newdata["passport"]["nationality"] = localVault.crypto.Encrypt(oldNationality, newitemEncKey, newitemMacKey);
        newdata["passport"]["issuingCountry"] = localVault.crypto.Encrypt(oldIssuingCountry, newitemEncKey, newitemMacKey);
        newdata["passport"]["passportNumber"] = localVault.crypto.Encrypt(oldPassportNumber, newitemEncKey, newitemMacKey);
        newdata["passport"]["passportType"] = localVault.crypto.Encrypt(oldPassportType, newitemEncKey, newitemMacKey);
        newdata["passport"]["nationalIdentificationNumber"] = localVault.crypto.Encrypt(oldNationalIdentificationNumber, newitemEncKey, newitemMacKey);
        newdata["passport"]["issuingAuthority"] = localVault.crypto.Encrypt(oldIssuingAuthority, newitemEncKey, newitemMacKey);
        newdata["passport"]["issueDate"] = localVault.crypto.Encrypt(oldIssueDate, newitemEncKey, newitemMacKey);
        newdata["passport"]["expirationDate"] = localVault.crypto.Encrypt(oldExpirationDate, newitemEncKey, newitemMacKey);
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
        newdata["type"] = 8;
        newdata["viewPassword"] = true;

        newfieldData["Fields"] = nlohmann::json::array();
        newfieldData["Name"] = localVault.crypto.Encrypt(oldName, newitemEncKey, newitemMacKey);
        newfieldData["Notes"] = localVault.crypto.Encrypt(oldNotes, newitemEncKey, newitemMacKey);

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
        OPENSSL_cleanse(oldSurname.data(), oldSurname.size());
        oldSurname.clear();
        OPENSSL_cleanse(oldGivenName.data(), oldGivenName.size());
        oldGivenName.clear();
        OPENSSL_cleanse(oldDateOfBirth.data(), oldDateOfBirth.size());
        oldDateOfBirth.clear();
        OPENSSL_cleanse(oldSex.data(), oldSex.size());
        oldSex.clear();
        OPENSSL_cleanse(oldBirthPlace.data(), oldBirthPlace.size());
        oldBirthPlace.clear();
        OPENSSL_cleanse(oldNationality.data(), oldNationality.size());
        oldNationality.clear();
        OPENSSL_cleanse(oldIssuingCountry.data(), oldIssuingCountry.size());
        oldIssuingCountry.clear();
        OPENSSL_cleanse(oldPassportNumber.data(), oldPassportNumber.size());
        oldPassportNumber.clear();
        OPENSSL_cleanse(oldPassportType.data(), oldPassportType.size());
        oldPassportType.clear();
        OPENSSL_cleanse(oldNationalIdentificationNumber.data(), oldNationalIdentificationNumber.size());
        oldNationalIdentificationNumber.clear();
        OPENSSL_cleanse(oldIssuingAuthority.data(), oldIssuingAuthority.size());
        oldIssuingAuthority.clear();
        OPENSSL_cleanse(oldIssueDate.data(), oldIssueDate.size());
        oldIssueDate.clear();
        OPENSSL_cleanse(oldExpirationDate.data(), oldExpirationDate.size());
        oldExpirationDate.clear();
        OPENSSL_cleanse(oldNotes.data(), oldNotes.size());
        oldNotes.clear();
        Botan::secure_scrub_memory(newitemEncKey.data(), newitemEncKey.size());
        Botan::secure_scrub_memory(newitemMacKey.data(), newitemMacKey.size());

        oldFavorite = false;
        oldReprompt = 0;

        newdata["revisionDate"] = getBitwardenTime();
        if (!localVault.features.checkAbove26_6_0()) {
            newdata["data"] = (std::string)newfieldData.dump();
        }
        std::optional<nlohmann::json> result = localVault.NewItem(newdata);
        if (!result.has_value()) {
            logger->warn("Failed to add New Item Online");
            newdata["createdOffline"] = true;
        } else {
            if (result.value().contains("id") && result.value()["id"].is_string()) {
                newdata["id"] = result.value()["id"];
            }
        }
        std::unique_lock<std::recursive_mutex> lock_vdset(localVault.session.vaultDataMutex);
        (*localVault.session.vaultData)["ciphers"].push_back(newdata);
        localVault.storage.write("vault.json", localVault.session.vaultData->dump(2));
        lock_vdset.unlock();

        id = newdata["id"];

        return this;
    }

    PassportItem* PassportItem::SetSurname(std::string& surname) {
        if (!init) return this;
        if (!data.contains("passport") || !data["passport"].is_object()) return this;

        fieldData["Surname"] = localVault.crypto.Encrypt(surname, itemEncKey, itemMacKey);
        data["passport"]["surname"] = localVault.crypto.Encrypt(surname, itemEncKey, itemMacKey);

        OPENSSL_cleanse(surname.data(), surname.size());
        surname.clear();
        return this;
    }

    PassportItem* PassportItem::SetGivenName(std::string& givenName) {
        if (!init) return this;
        if (!data.contains("passport") || !data["passport"].is_object()) return this;

        fieldData["GivenName"] = localVault.crypto.Encrypt(givenName, itemEncKey, itemMacKey);
        data["passport"]["givenName"] = localVault.crypto.Encrypt(givenName, itemEncKey, itemMacKey);

        OPENSSL_cleanse(givenName.data(), givenName.size());
        givenName.clear();
        return this;
    }

    PassportItem* PassportItem::SetDateOfBirth(std::string& dateOfBirth) {
        if (!init) return this;
        if (!data.contains("passport") || !data["passport"].is_object()) return this;

        fieldData["DateOfBirth"] = localVault.crypto.Encrypt(dateOfBirth, itemEncKey, itemMacKey);
        data["passport"]["dateOfBirth"] = localVault.crypto.Encrypt(dateOfBirth, itemEncKey, itemMacKey);

        OPENSSL_cleanse(dateOfBirth.data(), dateOfBirth.size());
        dateOfBirth.clear();
        return this;
    }

    PassportItem* PassportItem::SetSex(std::string& sex) {
        if (!init) return this;
        if (!data.contains("passport") || !data["passport"].is_object()) return this;

        fieldData["Sex"] = localVault.crypto.Encrypt(sex, itemEncKey, itemMacKey);
        data["passport"]["sex"] = localVault.crypto.Encrypt(sex, itemEncKey, itemMacKey);

        OPENSSL_cleanse(sex.data(), sex.size());
        sex.clear();
        return this;
    }

    PassportItem* PassportItem::SetBirthPlace(std::string& birthPlace) {
        if (!init) return this;
        if (!data.contains("passport") || !data["passport"].is_object()) return this;

        fieldData["BirthPlace"] = localVault.crypto.Encrypt(birthPlace, itemEncKey, itemMacKey);
        data["passport"]["birthPlace"] = localVault.crypto.Encrypt(birthPlace, itemEncKey, itemMacKey);

        OPENSSL_cleanse(birthPlace.data(), birthPlace.size());
        birthPlace.clear();
        return this;
    }

    PassportItem* PassportItem::SetNationality(std::string& nationality) {
        if (!init) return this;
        if (!data.contains("passport") || !data["passport"].is_object()) return this;

        fieldData["Nationality"] = localVault.crypto.Encrypt(nationality, itemEncKey, itemMacKey);
        data["passport"]["nationality"] = localVault.crypto.Encrypt(nationality, itemEncKey, itemMacKey);

        OPENSSL_cleanse(nationality.data(), nationality.size());
        nationality.clear();
        return this;
    }

    PassportItem* PassportItem::SetIssuingCountry(std::string& issuingCountry) {
        if (!init) return this;
        if (!data.contains("passport") || !data["passport"].is_object()) return this;

        fieldData["IssuingCountry"] = localVault.crypto.Encrypt(issuingCountry, itemEncKey, itemMacKey);
        data["passport"]["issuingCountry"] = localVault.crypto.Encrypt(issuingCountry, itemEncKey, itemMacKey);

        OPENSSL_cleanse(issuingCountry.data(), issuingCountry.size());
        issuingCountry.clear();
        return this;
    }

    PassportItem* PassportItem::SetPassportNumber(std::string& passportNumber) {
        if (!init) return this;
        if (!data.contains("passport") || !data["passport"].is_object()) return this;

        fieldData["PassportNumber"] = localVault.crypto.Encrypt(passportNumber, itemEncKey, itemMacKey);
        data["passport"]["passportNumber"] = localVault.crypto.Encrypt(passportNumber, itemEncKey, itemMacKey);

        OPENSSL_cleanse(passportNumber.data(), passportNumber.size());
        passportNumber.clear();
        return this;
    }

    PassportItem* PassportItem::SetPassportType(std::string& passportType) {
        if (!init) return this;
        if (!data.contains("passport") || !data["passport"].is_object()) return this;

        fieldData["PassportType"] = localVault.crypto.Encrypt(passportType, itemEncKey, itemMacKey);
        data["passport"]["passportType"] = localVault.crypto.Encrypt(passportType, itemEncKey, itemMacKey);

        OPENSSL_cleanse(passportType.data(), passportType.size());
        passportType.clear();
        return this;
    }

    PassportItem* PassportItem::SetNationalIdentificationNumber(std::string& nationalIdentificationNumber) {
        if (!init) return this;
        if (!data.contains("passport") || !data["passport"].is_object()) return this;

        fieldData["NationalIdentificationNumber"] = localVault.crypto.Encrypt(nationalIdentificationNumber, itemEncKey, itemMacKey);
        data["passport"]["nationalIdentificationNumber"] = localVault.crypto.Encrypt(nationalIdentificationNumber, itemEncKey, itemMacKey);

        OPENSSL_cleanse(nationalIdentificationNumber.data(), nationalIdentificationNumber.size());
        nationalIdentificationNumber.clear();
        return this;
    }

    PassportItem* PassportItem::SetIssuingAuthority(std::string& issuingAuthority) {
        if (!init) return this;
        if (!data.contains("passport") || !data["passport"].is_object()) return this;

        fieldData["IssuingAuthority"] = localVault.crypto.Encrypt(issuingAuthority, itemEncKey, itemMacKey);
        data["passport"]["issuingAuthority"] = localVault.crypto.Encrypt(issuingAuthority, itemEncKey, itemMacKey);

        OPENSSL_cleanse(issuingAuthority.data(), issuingAuthority.size());
        issuingAuthority.clear();
        return this;
    }

    PassportItem* PassportItem::SetIssueDate(std::string& issueDate) {
        if (!init) return this;
        if (!data.contains("passport") || !data["passport"].is_object()) return this;

        fieldData["IssueDate"] = localVault.crypto.Encrypt(issueDate, itemEncKey, itemMacKey);
        data["passport"]["issueDate"] = localVault.crypto.Encrypt(issueDate, itemEncKey, itemMacKey);

        OPENSSL_cleanse(issueDate.data(), issueDate.size());
        issueDate.clear();
        return this;
    }

    PassportItem* PassportItem::SetExpirationDate(std::string& expirationDate) {
        if (!init) return this;
        if (!data.contains("passport") || !data["passport"].is_object()) return this;

        fieldData["ExpirationDate"] = localVault.crypto.Encrypt(expirationDate, itemEncKey, itemMacKey);
        data["passport"]["expirationDate"] = localVault.crypto.Encrypt(expirationDate, itemEncKey, itemMacKey);

        OPENSSL_cleanse(expirationDate.data(), expirationDate.size());
        expirationDate.clear();
        return this;
    }

    PassportItem* PassportItem::GetSurname(std::string& surname) {
        if (!init) return this;
        if (!data["passport"].is_object()) return this;
        if (!data["passport"].contains("surname")) return this;
        if (!data["passport"]["surname"].is_string()) return this;

        surname = localVault.crypto.DecryptAsStr(data["passport"]["surname"], itemEncKey, itemMacKey);

        return this;
    }

    PassportItem* PassportItem::GetGivenName(std::string& givenName) {
        if (!init) return this;
        if (!data["passport"].is_object()) return this;
        if (!data["passport"].contains("givenName")) return this;
        if (!data["passport"]["givenName"].is_string()) return this;

        givenName = localVault.crypto.DecryptAsStr(data["passport"]["givenName"], itemEncKey, itemMacKey);

        return this;
    }

    PassportItem* PassportItem::GetDateOfBirth(std::string& dateOfBirth) {
        if (!init) return this;
        if (!data["passport"].is_object()) return this;
        if (!data["passport"].contains("dateOfBirth")) return this;
        if (!data["passport"]["dateOfBirth"].is_string()) return this;

        dateOfBirth = localVault.crypto.DecryptAsStr(data["passport"]["dateOfBirth"], itemEncKey, itemMacKey);

        return this;
    }

    PassportItem* PassportItem::GetSex(std::string& sex) {
        if (!init) return this;
        if (!data["passport"].is_object()) return this;
        if (!data["passport"].contains("sex")) return this;
        if (!data["passport"]["sex"].is_string()) return this;

        sex = localVault.crypto.DecryptAsStr(data["passport"]["sex"], itemEncKey, itemMacKey);

        return this;
    }

    PassportItem* PassportItem::GetBirthPlace(std::string& birthPlace) {
        if (!init) return this;
        if (!data["passport"].is_object()) return this;
        if (!data["passport"].contains("birthPlace")) return this;
        if (!data["passport"]["birthPlace"].is_string()) return this;

        birthPlace = localVault.crypto.DecryptAsStr(data["passport"]["birthPlace"], itemEncKey, itemMacKey);

        return this;
    }

    PassportItem* PassportItem::GetNationality(std::string& nationality) {
        if (!init) return this;
        if (!data["passport"].is_object()) return this;
        if (!data["passport"].contains("nationality")) return this;
        if (!data["passport"]["nationality"].is_string()) return this;

        nationality = localVault.crypto.DecryptAsStr(data["passport"]["nationality"], itemEncKey, itemMacKey);

        return this;
    }

    PassportItem* PassportItem::GetIssuingCountry(std::string& issuingCountry) {
        if (!init) return this;
        if (!data["passport"].is_object()) return this;
        if (!data["passport"].contains("issuingCountry")) return this;
        if (!data["passport"]["issuingCountry"].is_string()) return this;

        issuingCountry = localVault.crypto.DecryptAsStr(data["passport"]["issuingCountry"], itemEncKey, itemMacKey);

        return this;
    }

    PassportItem* PassportItem::GetPassportNumber(std::string& passportNumber) {
        if (!init) return this;
        if (!data["passport"].is_object()) return this;
        if (!data["passport"].contains("passportNumber")) return this;
        if (!data["passport"]["passportNumber"].is_string()) return this;

        passportNumber = localVault.crypto.DecryptAsStr(data["passport"]["passportNumber"], itemEncKey, itemMacKey);

        return this;
    }

    PassportItem* PassportItem::GetPassportType(std::string& passportType) {
        if (!init) return this;
        if (!data["passport"].is_object()) return this;
        if (!data["passport"].contains("passportType")) return this;
        if (!data["passport"]["passportType"].is_string()) return this;

        passportType = localVault.crypto.DecryptAsStr(data["passport"]["passportType"], itemEncKey, itemMacKey);

        return this;
    }

    PassportItem* PassportItem::GetNationalIdentificationNumber(std::string& nationalIdentificationNumber) {
        if (!init) return this;
        if (!data["passport"].is_object()) return this;
        if (!data["passport"].contains("nationalIdentificationNumber")) return this;
        if (!data["passport"]["nationalIdentificationNumber"].is_string()) return this;

        nationalIdentificationNumber = localVault.crypto.DecryptAsStr(data["passport"]["nationalIdentificationNumber"], itemEncKey, itemMacKey);

        return this;
    }

    PassportItem* PassportItem::GetIssuingAuthority(std::string& issuingAuthority) {
        if (!init) return this;
        if (!data["passport"].is_object()) return this;
        if (!data["passport"].contains("issuingAuthority")) return this;
        if (!data["passport"]["issuingAuthority"].is_string()) return this;

        issuingAuthority = localVault.crypto.DecryptAsStr(data["passport"]["issuingAuthority"], itemEncKey, itemMacKey);

        return this;
    }

    PassportItem* PassportItem::GetIssueDate(std::string& issueDate) {
        if (!init) return this;
        if (!data["passport"].is_object()) return this;
        if (!data["passport"].contains("issueDate")) return this;
        if (!data["passport"]["issueDate"].is_string()) return this;

        issueDate = localVault.crypto.DecryptAsStr(data["passport"]["issueDate"], itemEncKey, itemMacKey);

        return this;
    }

    PassportItem* PassportItem::GetExpirationDate(std::string& expirationDate) {
        if (!init) return this;
        if (!data["passport"].is_object()) return this;
        if (!data["passport"].contains("expirationDate")) return this;
        if (!data["passport"]["expirationDate"].is_string()) return this;

        expirationDate = localVault.crypto.DecryptAsStr(data["passport"]["expirationDate"], itemEncKey, itemMacKey);

        return this;
    }

    PassportItem* PassportItem::GetType(CipherType& val) {
        val = CipherType::Passport;
        return this;
    }
}