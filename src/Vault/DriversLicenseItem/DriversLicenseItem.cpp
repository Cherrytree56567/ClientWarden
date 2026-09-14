#include "DriversLicenseItem.h"
#include "Vault.h"

namespace ClientWarden {
    DriversLicenseItem::DriversLicenseItem(Vault& vault, std::string uuid) : GenericItemImpl<DriversLicenseItem>(vault, uuid) {
        init = false;
        if (data.contains("type") && data["type"].is_number()) {
            if (data["type"].get<int>() == 7) {
                init = true;
            }
        }
        if (!data.contains("driversLicense")) {
            init = false;
        }
    }

    DriversLicenseItem::DriversLicenseItem(Vault& vault) : GenericItemImpl<DriversLicenseItem>(vault) {
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
        data["driversLicense"] = nlohmann::json::object();
        data["driversLicense"]["firstName"] = localVault.crypto.Encrypt("", itemEncKey, itemMacKey);
        data["driversLicense"]["middleName"] = localVault.crypto.Encrypt("", itemEncKey, itemMacKey);
        data["driversLicense"]["lastName"] = localVault.crypto.Encrypt("", itemEncKey, itemMacKey);
        data["driversLicense"]["dateOfBirth"] = localVault.crypto.Encrypt("", itemEncKey, itemMacKey);
        data["driversLicense"]["licenseNumber"] = localVault.crypto.Encrypt("", itemEncKey, itemMacKey);
        data["driversLicense"]["issuingCountry"] = localVault.crypto.Encrypt("", itemEncKey, itemMacKey);
        data["driversLicense"]["issuingState"] = localVault.crypto.Encrypt("", itemEncKey, itemMacKey);
        data["driversLicense"]["issueDate"] = localVault.crypto.Encrypt("", itemEncKey, itemMacKey);
        data["driversLicense"]["expirationDate"] = localVault.crypto.Encrypt("", itemEncKey, itemMacKey);
        data["driversLicense"]["issuingAuthority"] = localVault.crypto.Encrypt("", itemEncKey, itemMacKey);
        data["driversLicense"]["licenseClass"] = localVault.crypto.Encrypt("", itemEncKey, itemMacKey);
        data["passport"] = nullptr;
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
        data["type"] = 7;
        data["viewPassword"] = true;

        fieldData["Fields"] = nlohmann::json::array();
        fieldData["Name"] = localVault.crypto.Encrypt("", itemEncKey, itemMacKey);
        fieldData["Notes"] = nullptr;

        init = true;
    }

    DriversLicenseItem* DriversLicenseItem::Duplicate(std::string& id) {
        auto keys = localVault.crypto.generateEncMacKeys();
        auto newitemEncKey = keys.first;
        auto newitemMacKey = keys.second;

        /*
         * SECRET DATA
        */
        std::string oldName;
        std::string oldFirstName;
        std::string oldMiddleName;
        std::string oldLastName;
        std::string oldDateOfBirth;
        std::string oldLicenseNumber;
        std::string oldIssuingCountry;
        std::string oldIssuingState;
        std::string oldIssueDate;
        std::string oldExpirationDate;
        std::string oldIssuingAuthority;
        std::string oldLicenseClass;
        std::string oldNotes;
        std::vector<std::tuple<CustomFieldType, std::string, std::string>> oldFields;

        bool oldFavorite = false;
        int oldReprompt = 0;

        if (data.contains("name") && data["name"].is_string()) {
            oldName = localVault.crypto.DecryptAsStr(data["name"], itemEncKey, itemMacKey);
        }

        if (data.contains("driversLicense") && data["driversLicense"].is_object()) {
            if (data["driversLicense"].contains("firstName") && data["driversLicense"]["firstName"].is_string()) {
                oldFirstName = localVault.crypto.DecryptAsStr(data["driversLicense"]["firstName"], itemEncKey, itemMacKey);
            }
            if (data["driversLicense"].contains("middleName") && data["driversLicense"]["middleName"].is_string()) {
                oldMiddleName = localVault.crypto.DecryptAsStr(data["driversLicense"]["middleName"], itemEncKey, itemMacKey);
            }
            if (data["driversLicense"].contains("lastName") && data["driversLicense"]["lastName"].is_string()) {
                oldLastName = localVault.crypto.DecryptAsStr(data["driversLicense"]["lastName"], itemEncKey, itemMacKey);
            }
            if (data["driversLicense"].contains("dateOfBirth") && data["driversLicense"]["dateOfBirth"].is_string()) {
                oldDateOfBirth = localVault.crypto.DecryptAsStr(data["driversLicense"]["dateOfBirth"], itemEncKey, itemMacKey);
            }
            if (data["driversLicense"].contains("licenseNumber") && data["driversLicense"]["licenseNumber"].is_string()) {
                oldLicenseNumber = localVault.crypto.DecryptAsStr(data["driversLicense"]["licenseNumber"], itemEncKey, itemMacKey);
            }
            if (data["driversLicense"].contains("issuingCountry") && data["driversLicense"]["issuingCountry"].is_string()) {
                oldIssuingCountry = localVault.crypto.DecryptAsStr(data["driversLicense"]["issuingCountry"], itemEncKey, itemMacKey);
            }
            if (data["driversLicense"].contains("issuingState") && data["driversLicense"]["issuingState"].is_string()) {
                oldIssuingState = localVault.crypto.DecryptAsStr(data["driversLicense"]["issuingState"], itemEncKey, itemMacKey);
            }
            if (data["driversLicense"].contains("issueDate") && data["driversLicense"]["issueDate"].is_string()) {
                oldIssueDate = localVault.crypto.DecryptAsStr(data["driversLicense"]["issueDate"], itemEncKey, itemMacKey);
            }
            if (data["driversLicense"].contains("expirationDate") && data["driversLicense"]["expirationDate"].is_string()) {
                oldExpirationDate = localVault.crypto.DecryptAsStr(data["driversLicense"]["expirationDate"], itemEncKey, itemMacKey);
            }
            if (data["driversLicense"].contains("issuingAuthority") && data["driversLicense"]["issuingAuthority"].is_string()) {
                oldIssuingAuthority = localVault.crypto.DecryptAsStr(data["driversLicense"]["issuingAuthority"], itemEncKey, itemMacKey);
            }
            if (data["driversLicense"].contains("licenseClass") && data["driversLicense"]["licenseClass"].is_string()) {
                oldLicenseClass = localVault.crypto.DecryptAsStr(data["driversLicense"]["licenseClass"], itemEncKey, itemMacKey);
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
        newdata["passport"] = nullptr;
        newdata["login"] = nullptr;
        newdata["bankAccount"] = nullptr;
        newdata["driversLicense"] = nlohmann::json::object();
        newdata["driversLicense"]["firstName"] = localVault.crypto.Encrypt(oldFirstName, newitemEncKey, newitemMacKey);
        newdata["driversLicense"]["middleName"] = localVault.crypto.Encrypt(oldMiddleName, newitemEncKey, newitemMacKey);
        newdata["driversLicense"]["lastName"] = localVault.crypto.Encrypt(oldLastName, newitemEncKey, newitemMacKey);
        newdata["driversLicense"]["dateOfBirth"] = localVault.crypto.Encrypt(oldDateOfBirth, newitemEncKey, newitemMacKey);
        newdata["driversLicense"]["licenseNumber"] = localVault.crypto.Encrypt(oldLicenseNumber, newitemEncKey, newitemMacKey);
        newdata["driversLicense"]["issuingCountry"] = localVault.crypto.Encrypt(oldIssuingCountry, newitemEncKey, newitemMacKey);
        newdata["driversLicense"]["issuingState"] = localVault.crypto.Encrypt(oldIssuingState, newitemEncKey, newitemMacKey);
        newdata["driversLicense"]["issueDate"] = localVault.crypto.Encrypt(oldIssueDate, newitemEncKey, newitemMacKey);
        newdata["driversLicense"]["expirationDate"] = localVault.crypto.Encrypt(oldExpirationDate, newitemEncKey, newitemMacKey);
        newdata["driversLicense"]["issuingAuthority"] = localVault.crypto.Encrypt(oldIssuingAuthority, newitemEncKey, newitemMacKey);
        newdata["driversLicense"]["licenseClass"] = localVault.crypto.Encrypt(oldLicenseClass, newitemEncKey, newitemMacKey);
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
        newdata["type"] = 7;
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
        OPENSSL_cleanse(oldFirstName.data(), oldFirstName.size());
        oldFirstName.clear();
        OPENSSL_cleanse(oldMiddleName.data(), oldMiddleName.size());
        oldMiddleName.clear();
        OPENSSL_cleanse(oldLastName.data(), oldLastName.size());
        oldLastName.clear();
        OPENSSL_cleanse(oldDateOfBirth.data(), oldDateOfBirth.size());
        oldDateOfBirth.clear();
        OPENSSL_cleanse(oldLicenseNumber.data(), oldLicenseNumber.size());
        oldLicenseNumber.clear();
        OPENSSL_cleanse(oldIssuingCountry.data(), oldIssuingCountry.size());
        oldIssuingCountry.clear();
        OPENSSL_cleanse(oldIssuingState.data(), oldIssuingState.size());
        oldIssuingState.clear();
        OPENSSL_cleanse(oldIssueDate.data(), oldIssueDate.size());
        oldIssueDate.clear();
        OPENSSL_cleanse(oldExpirationDate.data(), oldExpirationDate.size());
        oldExpirationDate.clear();
        OPENSSL_cleanse(oldIssuingAuthority.data(), oldIssuingAuthority.size());
        oldIssuingAuthority.clear();
        OPENSSL_cleanse(oldLicenseClass.data(), oldLicenseClass.size());
        oldLicenseClass.clear();
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

    DriversLicenseItem* DriversLicenseItem::SetFirstName(std::string& firstName) {
        if (!init) return this;
        if (!data.contains("driversLicense") || !data["driversLicense"].is_object()) return this;

        fieldData["FirstName"] = localVault.crypto.Encrypt(firstName, itemEncKey, itemMacKey);
        data["driversLicense"]["firstName"] = localVault.crypto.Encrypt(firstName, itemEncKey, itemMacKey);

        OPENSSL_cleanse(firstName.data(), firstName.size());
        firstName.clear();
        return this;
    }

    DriversLicenseItem* DriversLicenseItem::SetMiddleName(std::string& middleName) {
        if (!init) return this;
        if (!data.contains("driversLicense") || !data["driversLicense"].is_object()) return this;

        fieldData["MiddleName"] = localVault.crypto.Encrypt(middleName, itemEncKey, itemMacKey);
        data["driversLicense"]["middleName"] = localVault.crypto.Encrypt(middleName, itemEncKey, itemMacKey);

        OPENSSL_cleanse(middleName.data(), middleName.size());
        middleName.clear();
        return this;
    }

    DriversLicenseItem* DriversLicenseItem::SetLastName(std::string& lastName) {
        if (!init) return this;
        if (!data.contains("driversLicense") || !data["driversLicense"].is_object()) return this;

        fieldData["LastName"] = localVault.crypto.Encrypt(lastName, itemEncKey, itemMacKey);
        data["driversLicense"]["lastName"] = localVault.crypto.Encrypt(lastName, itemEncKey, itemMacKey);

        OPENSSL_cleanse(lastName.data(), lastName.size());
        lastName.clear();
        return this;
    }

    DriversLicenseItem* DriversLicenseItem::SetDateOfBirth(std::string& dateOfBirth) {
        if (!init) return this;
        if (!data.contains("driversLicense") || !data["driversLicense"].is_object()) return this;

        fieldData["DateOfBirth"] = localVault.crypto.Encrypt(dateOfBirth, itemEncKey, itemMacKey);
        data["driversLicense"]["dateOfBirth"] = localVault.crypto.Encrypt(dateOfBirth, itemEncKey, itemMacKey);

        OPENSSL_cleanse(dateOfBirth.data(), dateOfBirth.size());
        dateOfBirth.clear();
        return this;
    }

    DriversLicenseItem* DriversLicenseItem::SetLicenseNumber(std::string& licenseNumber) {
        if (!init) return this;
        if (!data.contains("driversLicense") || !data["driversLicense"].is_object()) return this;

        fieldData["LicenseNumber"] = localVault.crypto.Encrypt(licenseNumber, itemEncKey, itemMacKey);
        data["driversLicense"]["licenseNumber"] = localVault.crypto.Encrypt(licenseNumber, itemEncKey, itemMacKey);

        OPENSSL_cleanse(licenseNumber.data(), licenseNumber.size());
        licenseNumber.clear();
        return this;
    }

    DriversLicenseItem* DriversLicenseItem::SetIssuingCountry(std::string& issuingCountry) {
        if (!init) return this;
        if (!data.contains("driversLicense") || !data["driversLicense"].is_object()) return this;

        fieldData["IssuingCountry"] = localVault.crypto.Encrypt(issuingCountry, itemEncKey, itemMacKey);
        data["driversLicense"]["issuingCountry"] = localVault.crypto.Encrypt(issuingCountry, itemEncKey, itemMacKey);

        OPENSSL_cleanse(issuingCountry.data(), issuingCountry.size());
        issuingCountry.clear();
        return this;
    }

    DriversLicenseItem* DriversLicenseItem::SetIssuingState(std::string& issuingState) {
        if (!init) return this;
        if (!data.contains("driversLicense") || !data["driversLicense"].is_object()) return this;

        fieldData["IssuingState"] = localVault.crypto.Encrypt(issuingState, itemEncKey, itemMacKey);
        data["driversLicense"]["issuingState"] = localVault.crypto.Encrypt(issuingState, itemEncKey, itemMacKey);

        OPENSSL_cleanse(issuingState.data(), issuingState.size());
        issuingState.clear();
        return this;
    }

    DriversLicenseItem* DriversLicenseItem::SetIssueDate(std::string& issueDate) {
        if (!init) return this;
        if (!data.contains("driversLicense") || !data["driversLicense"].is_object()) return this;

        fieldData["IssueDate"] = localVault.crypto.Encrypt(issueDate, itemEncKey, itemMacKey);
        data["driversLicense"]["issueDate"] = localVault.crypto.Encrypt(issueDate, itemEncKey, itemMacKey);

        OPENSSL_cleanse(issueDate.data(), issueDate.size());
        issueDate.clear();
        return this;
    }

    DriversLicenseItem* DriversLicenseItem::SetExpirationDate(std::string& expirationDate) {
        if (!init) return this;
        if (!data.contains("driversLicense") || !data["driversLicense"].is_object()) return this;

        fieldData["ExpirationDate"] = localVault.crypto.Encrypt(expirationDate, itemEncKey, itemMacKey);
        data["driversLicense"]["expirationDate"] = localVault.crypto.Encrypt(expirationDate, itemEncKey, itemMacKey);

        OPENSSL_cleanse(expirationDate.data(), expirationDate.size());
        expirationDate.clear();
        return this;
    }

    DriversLicenseItem* DriversLicenseItem::SetIssuingAuthority(std::string& issuingAuthority) {
        if (!init) return this;
        if (!data.contains("driversLicense") || !data["driversLicense"].is_object()) return this;

        fieldData["IssuingAuthority"] = localVault.crypto.Encrypt(issuingAuthority, itemEncKey, itemMacKey);
        data["driversLicense"]["issuingAuthority"] = localVault.crypto.Encrypt(issuingAuthority, itemEncKey, itemMacKey);

        OPENSSL_cleanse(issuingAuthority.data(), issuingAuthority.size());
        issuingAuthority.clear();
        return this;
    }

    DriversLicenseItem* DriversLicenseItem::SetLicenseClass(std::string& licenseClass) {
        if (!init) return this;
        if (!data.contains("driversLicense") || !data["driversLicense"].is_object()) return this;

        fieldData["LicenseClass"] = localVault.crypto.Encrypt(licenseClass, itemEncKey, itemMacKey);
        data["driversLicense"]["licenseClass"] = localVault.crypto.Encrypt(licenseClass, itemEncKey, itemMacKey);

        OPENSSL_cleanse(licenseClass.data(), licenseClass.size());
        licenseClass.clear();
        return this;
    }

    DriversLicenseItem* DriversLicenseItem::GetFirstName(std::string& firstName) {
        if (!init) return this;
        if (!data["driversLicense"].is_object()) return this;
        if (!data["driversLicense"].contains("firstName")) return this;
        if (!data["driversLicense"]["firstName"].is_string()) return this;

        firstName = localVault.crypto.DecryptAsStr(data["driversLicense"]["firstName"], itemEncKey, itemMacKey);

        return this;
    }

    DriversLicenseItem* DriversLicenseItem::GetMiddleName(std::string& middleName) {
        if (!init) return this;
        if (!data["driversLicense"].is_object()) return this;
        if (!data["driversLicense"].contains("middleName")) return this;
        if (!data["driversLicense"]["middleName"].is_string()) return this;

        middleName = localVault.crypto.DecryptAsStr(data["driversLicense"]["middleName"], itemEncKey, itemMacKey);

        return this;
    }

    DriversLicenseItem* DriversLicenseItem::GetLastName(std::string& lastName) {
        if (!init) return this;
        if (!data["driversLicense"].is_object()) return this;
        if (!data["driversLicense"].contains("lastName")) return this;
        if (!data["driversLicense"]["lastName"].is_string()) return this;

        lastName = localVault.crypto.DecryptAsStr(data["driversLicense"]["lastName"], itemEncKey, itemMacKey);

        return this;
    }

    DriversLicenseItem* DriversLicenseItem::GetDateOfBirth(std::string& dateOfBirth) {
        if (!init) return this;
        if (!data["driversLicense"].is_object()) return this;
        if (!data["driversLicense"].contains("dateOfBirth")) return this;
        if (!data["driversLicense"]["dateOfBirth"].is_string()) return this;

        dateOfBirth = localVault.crypto.DecryptAsStr(data["driversLicense"]["dateOfBirth"], itemEncKey, itemMacKey);

        return this;
    }

    DriversLicenseItem* DriversLicenseItem::GetLicenseNumber(std::string& licenseNumber) {
        if (!init) return this;
        if (!data["driversLicense"].is_object()) return this;
        if (!data["driversLicense"].contains("licenseNumber")) return this;
        if (!data["driversLicense"]["licenseNumber"].is_string()) return this;

        licenseNumber = localVault.crypto.DecryptAsStr(data["driversLicense"]["licenseNumber"], itemEncKey, itemMacKey);

        return this;
    }

    DriversLicenseItem* DriversLicenseItem::GetIssuingCountry(std::string& issuingCountry) {
        if (!init) return this;
        if (!data["driversLicense"].is_object()) return this;
        if (!data["driversLicense"].contains("issuingCountry")) return this;
        if (!data["driversLicense"]["issuingCountry"].is_string()) return this;

        issuingCountry = localVault.crypto.DecryptAsStr(data["driversLicense"]["issuingCountry"], itemEncKey, itemMacKey);

        return this;
    }

    DriversLicenseItem* DriversLicenseItem::GetIssuingState(std::string& issuingState) {
        if (!init) return this;
        if (!data["driversLicense"].is_object()) return this;
        if (!data["driversLicense"].contains("issuingState")) return this;
        if (!data["driversLicense"]["issuingState"].is_string()) return this;

        issuingState = localVault.crypto.DecryptAsStr(data["driversLicense"]["issuingState"], itemEncKey, itemMacKey);

        return this;
    }

    DriversLicenseItem* DriversLicenseItem::GetIssueDate(std::string& issueDate) {
        if (!init) return this;
        if (!data["driversLicense"].is_object()) return this;
        if (!data["driversLicense"].contains("issueDate")) return this;
        if (!data["driversLicense"]["issueDate"].is_string()) return this;

        issueDate = localVault.crypto.DecryptAsStr(data["driversLicense"]["issueDate"], itemEncKey, itemMacKey);

        return this;
    }

    DriversLicenseItem* DriversLicenseItem::GetExpirationDate(std::string& expirationDate) {
        if (!init) return this;
        if (!data["driversLicense"].is_object()) return this;
        if (!data["driversLicense"].contains("expirationDate")) return this;
        if (!data["driversLicense"]["expirationDate"].is_string()) return this;

        expirationDate = localVault.crypto.DecryptAsStr(data["driversLicense"]["expirationDate"], itemEncKey, itemMacKey);

        return this;
    }

    DriversLicenseItem* DriversLicenseItem::GetIssuingAuthority(std::string& issuingAuthority) {
        if (!init) return this;
        if (!data["driversLicense"].is_object()) return this;
        if (!data["driversLicense"].contains("issuingAuthority")) return this;
        if (!data["driversLicense"]["issuingAuthority"].is_string()) return this;

        issuingAuthority = localVault.crypto.DecryptAsStr(data["driversLicense"]["issuingAuthority"], itemEncKey, itemMacKey);

        return this;
    }

    DriversLicenseItem* DriversLicenseItem::GetLicenseClass(std::string& licenseClass) {
        if (!init) return this;
        if (!data["driversLicense"].is_object()) return this;
        if (!data["driversLicense"].contains("licenseClass")) return this;
        if (!data["driversLicense"]["licenseClass"].is_string()) return this;

        licenseClass = localVault.crypto.DecryptAsStr(data["driversLicense"]["licenseClass"], itemEncKey, itemMacKey);

        return this;
    }

    DriversLicenseItem* DriversLicenseItem::GetType(CipherType& val) {
        val = CipherType::DriversLicense;
        return this;
    }
}