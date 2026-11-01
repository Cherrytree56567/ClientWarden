#include "BankAccountItem.h"
#include "Vault.h"

namespace ClientWarden {
    BankAccountItem::BankAccountItem(Vault& vault, std::string uuid) : GenericItemImpl<BankAccountItem>(vault, uuid) {
        init = false;
        if (data.contains("type") && data["type"].is_number()) {
            if (data["type"].get<int>() == 6) {
                init = true;
            }
        }
        if (!data.contains("bankAccount")) {
            init = false;
        }
    }

    BankAccountItem::BankAccountItem(Vault& vault) : GenericItemImpl<BankAccountItem>(vault) {
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
        data["bankAccount"] = nlohmann::json::object();
        data["bankAccount"]["bankName"] = localVault.crypto.Encrypt("", itemEncKey, itemMacKey);
        data["bankAccount"]["nameOnAccount"] = localVault.crypto.Encrypt("", itemEncKey, itemMacKey);
        data["bankAccount"]["accountType"] = localVault.crypto.Encrypt("", itemEncKey, itemMacKey);
        data["bankAccount"]["accountNumber"] = localVault.crypto.Encrypt("", itemEncKey, itemMacKey);
        data["bankAccount"]["routingNumber"] = localVault.crypto.Encrypt("", itemEncKey, itemMacKey);
        data["bankAccount"]["branchNumber"] = localVault.crypto.Encrypt("", itemEncKey, itemMacKey);
        data["bankAccount"]["pin"] = localVault.crypto.Encrypt("", itemEncKey, itemMacKey);
        data["bankAccount"]["swiftCode"] = localVault.crypto.Encrypt("", itemEncKey, itemMacKey);
        data["bankAccount"]["iban"] = localVault.crypto.Encrypt("", itemEncKey, itemMacKey);
        data["bankAccount"]["bankContactPhone"] = localVault.crypto.Encrypt("", itemEncKey, itemMacKey);
        data["driversLicense"] = nullptr;
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
        data["type"] = 6;
        data["viewPassword"] = true;

        fieldData["Fields"] = nlohmann::json::array();
        fieldData["Name"] = localVault.crypto.Encrypt("", itemEncKey, itemMacKey);
        fieldData["Notes"] = nullptr;

        init = true;
    }

    BankAccountItem* BankAccountItem::Duplicate(std::string& id) {
        auto keys = localVault.crypto.generateEncMacKeys();
        auto newitemEncKey = keys.first;
        auto newitemMacKey = keys.second;

        /*
         * SECRET DATA
        */
        std::string oldName;
        std::string oldBankName;
        std::string oldNameOnAccount;
        std::string oldAccountType;
        std::string oldAccountNumber;
        std::string oldRoutingNumber;
        std::string oldBranchNumber;
        std::string oldPin;
        std::string oldSwiftCode;
        std::string oldIBAN;
        std::string oldBankContactPhone;
        std::string oldNotes;
        std::vector<std::tuple<CustomFieldType, std::string, std::string>> oldFields;

        bool oldFavorite = false;
        int oldReprompt = 0;

        if (data.contains("name") && data["name"].is_string()) {
            oldName = localVault.crypto.DecryptAsStr(data["name"], itemEncKey, itemMacKey);
        }

        if (data.contains("bankAccount") && data["bankAccount"].is_object()) {
            if (data["bankAccount"].contains("bankName") && data["bankAccount"]["bankName"].is_string()) {
                oldBankName = localVault.crypto.DecryptAsStr(data["bankAccount"]["bankName"], itemEncKey, itemMacKey);
            }
            if (data["bankAccount"].contains("nameOnAccount") && data["bankAccount"]["nameOnAccount"].is_string()) {
                oldNameOnAccount = localVault.crypto.DecryptAsStr(data["bankAccount"]["nameOnAccount"], itemEncKey, itemMacKey);
            }
            if (data["bankAccount"].contains("accountType") && data["bankAccount"]["accountType"].is_string()) {
                oldAccountType = localVault.crypto.DecryptAsStr(data["bankAccount"]["accountType"], itemEncKey, itemMacKey);
            }
            if (data["bankAccount"].contains("accountNumber") && data["bankAccount"]["accountNumber"].is_string()) {
                oldAccountNumber = localVault.crypto.DecryptAsStr(data["bankAccount"]["accountNumber"], itemEncKey, itemMacKey);
            }
            if (data["bankAccount"].contains("routingNumber") && data["bankAccount"]["routingNumber"].is_string()) {
                oldRoutingNumber = localVault.crypto.DecryptAsStr(data["bankAccount"]["routingNumber"], itemEncKey, itemMacKey);
            }
            if (data["bankAccount"].contains("branchNumber") && data["bankAccount"]["branchNumber"].is_string()) {
                oldBranchNumber = localVault.crypto.DecryptAsStr(data["bankAccount"]["branchNumber"], itemEncKey, itemMacKey);
            }
            if (data["bankAccount"].contains("pin") && data["bankAccount"]["pin"].is_string()) {
                oldPin = localVault.crypto.DecryptAsStr(data["bankAccount"]["pin"], itemEncKey, itemMacKey);
            }
            if (data["bankAccount"].contains("swiftCode") && data["bankAccount"]["swiftCode"].is_string()) {
                oldSwiftCode = localVault.crypto.DecryptAsStr(data["bankAccount"]["swiftCode"], itemEncKey, itemMacKey);
            }
            if (data["bankAccount"].contains("iban") && data["bankAccount"]["iban"].is_string()) {
                oldIBAN = localVault.crypto.DecryptAsStr(data["bankAccount"]["iban"], itemEncKey, itemMacKey);
            }
            if (data["bankAccount"].contains("bankContactPhone") && data["bankAccount"]["bankContactPhone"].is_string()) {
                oldBankContactPhone = localVault.crypto.DecryptAsStr(data["bankAccount"]["bankContactPhone"], itemEncKey, itemMacKey);
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
        newdata["passport"] = nullptr;
        newdata["login"] = nullptr;
        newdata["bankAccount"] = nlohmann::json::object();
        newdata["bankAccount"]["bankName"] = localVault.crypto.Encrypt(oldBankName, newitemEncKey, newitemMacKey);
        newdata["bankAccount"]["nameOnAccount"] = localVault.crypto.Encrypt(oldNameOnAccount, newitemEncKey, newitemMacKey);
        newdata["bankAccount"]["accountType"] = localVault.crypto.Encrypt(oldAccountType, newitemEncKey, newitemMacKey);
        newdata["bankAccount"]["accountNumber"] = localVault.crypto.Encrypt(oldAccountNumber, newitemEncKey, newitemMacKey);
        newdata["bankAccount"]["routingNumber"] = localVault.crypto.Encrypt(oldRoutingNumber, newitemEncKey, newitemMacKey);
        newdata["bankAccount"]["branchNumber"] = localVault.crypto.Encrypt(oldBranchNumber, newitemEncKey, newitemMacKey);
        newdata["bankAccount"]["pin"] = localVault.crypto.Encrypt(oldPin, newitemEncKey, newitemMacKey);
        newdata["bankAccount"]["swiftCode"] = localVault.crypto.Encrypt(oldSwiftCode, newitemEncKey, newitemMacKey);
        newdata["bankAccount"]["iban"] = localVault.crypto.Encrypt(oldIBAN, newitemEncKey, newitemMacKey);
        newdata["bankAccount"]["bankContactPhone"] = localVault.crypto.Encrypt(oldBankContactPhone, newitemEncKey, newitemMacKey);
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
        newdata["type"] = 6;
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
        OPENSSL_cleanse(oldBankName.data(), oldBankName.size());
        oldBankName.clear();
        OPENSSL_cleanse(oldNameOnAccount.data(), oldNameOnAccount.size());
        oldNameOnAccount.clear();
        OPENSSL_cleanse(oldAccountType.data(), oldAccountType.size());
        oldAccountType.clear();
        OPENSSL_cleanse(oldAccountNumber.data(), oldAccountNumber.size());
        oldAccountNumber.clear();
        OPENSSL_cleanse(oldRoutingNumber.data(), oldRoutingNumber.size());
        oldRoutingNumber.clear();
        OPENSSL_cleanse(oldBranchNumber.data(), oldBranchNumber.size());
        oldBranchNumber.clear();
        OPENSSL_cleanse(oldPin.data(), oldPin.size());
        oldPin.clear();
        OPENSSL_cleanse(oldSwiftCode.data(), oldSwiftCode.size());
        oldSwiftCode.clear();
        OPENSSL_cleanse(oldIBAN.data(), oldIBAN.size());
        oldIBAN.clear();
        OPENSSL_cleanse(oldBankContactPhone.data(), oldBankContactPhone.size());
        oldBankContactPhone.clear();
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

    BankAccountItem* BankAccountItem::SetBankName(std::string& bankName) {
        if (!init) return this;
        if (!data.contains("bankAccount") || !data["bankAccount"].is_object()) return this;

        fieldData["BankName"] = localVault.crypto.Encrypt(bankName, itemEncKey, itemMacKey);
        data["bankAccount"]["bankName"] = localVault.crypto.Encrypt(bankName, itemEncKey, itemMacKey);

        OPENSSL_cleanse(bankName.data(), bankName.size());
        bankName.clear();
        return this;
    }

    BankAccountItem* BankAccountItem::SetNameOnAccount(std::string& nameOnAccount) {
        if (!init) return this;
        if (!data.contains("bankAccount") || !data["bankAccount"].is_object()) return this;

        fieldData["NameOnAccount"] = localVault.crypto.Encrypt(nameOnAccount, itemEncKey, itemMacKey);
        data["bankAccount"]["nameOnAccount"] = localVault.crypto.Encrypt(nameOnAccount, itemEncKey, itemMacKey);

        OPENSSL_cleanse(nameOnAccount.data(), nameOnAccount.size());
        nameOnAccount.clear();
        return this;
    }

    BankAccountItem* BankAccountItem::SetAccountType(std::string& accountType) {
        if (!init) return this;
        if (!data.contains("bankAccount") || !data["bankAccount"].is_object()) return this;

        fieldData["AccountType"] = localVault.crypto.Encrypt(accountType, itemEncKey, itemMacKey);
        data["bankAccount"]["accountType"] = localVault.crypto.Encrypt(accountType, itemEncKey, itemMacKey);

        OPENSSL_cleanse(accountType.data(), accountType.size());
        accountType.clear();
        return this;
    }

    BankAccountItem* BankAccountItem::SetAccountNumber(std::string& accountNumber) {
        if (!init) return this;
        if (!data.contains("bankAccount") || !data["bankAccount"].is_object()) return this;

        fieldData["AccountNumber"] = localVault.crypto.Encrypt(accountNumber, itemEncKey, itemMacKey);
        data["bankAccount"]["accountNumber"] = localVault.crypto.Encrypt(accountNumber, itemEncKey, itemMacKey);

        OPENSSL_cleanse(accountNumber.data(), accountNumber.size());
        accountNumber.clear();
        return this;
    }

    BankAccountItem* BankAccountItem::SetRoutingNumber(std::string& routingNumber) {
        if (!init) return this;
        if (!data.contains("bankAccount") || !data["bankAccount"].is_object()) return this;

        fieldData["RoutingNumber"] = localVault.crypto.Encrypt(routingNumber, itemEncKey, itemMacKey);
        data["bankAccount"]["routingNumber"] = localVault.crypto.Encrypt(routingNumber, itemEncKey, itemMacKey);

        OPENSSL_cleanse(routingNumber.data(), routingNumber.size());
        routingNumber.clear();
        return this;
    }

    BankAccountItem* BankAccountItem::SetBranchNumber(std::string& branchNumber) {
        if (!init) return this;
        if (!data.contains("bankAccount") || !data["bankAccount"].is_object()) return this;

        fieldData["BranchNumber"] = localVault.crypto.Encrypt(branchNumber, itemEncKey, itemMacKey);
        data["bankAccount"]["branchNumber"] = localVault.crypto.Encrypt(branchNumber, itemEncKey, itemMacKey);

        OPENSSL_cleanse(branchNumber.data(), branchNumber.size());
        branchNumber.clear();
        return this;
    }

    BankAccountItem* BankAccountItem::SetPin(std::string& pin) {
        if (!init) return this;
        if (!data.contains("bankAccount") || !data["bankAccount"].is_object()) return this;

        fieldData["Pin"] = localVault.crypto.Encrypt(pin, itemEncKey, itemMacKey);
        data["bankAccount"]["pin"] = localVault.crypto.Encrypt(pin, itemEncKey, itemMacKey);

        OPENSSL_cleanse(pin.data(), pin.size());
        pin.clear();
        return this;
    }

    BankAccountItem* BankAccountItem::SetSwiftCode(std::string& swiftCode) {
        if (!init) return this;
        if (!data.contains("bankAccount") || !data["bankAccount"].is_object()) return this;

        fieldData["SwiftCode"] = localVault.crypto.Encrypt(swiftCode, itemEncKey, itemMacKey);
        data["bankAccount"]["swiftCode"] = localVault.crypto.Encrypt(swiftCode, itemEncKey, itemMacKey);

        OPENSSL_cleanse(swiftCode.data(), swiftCode.size());
        swiftCode.clear();
        return this;
    }

    BankAccountItem* BankAccountItem::SetIBAN(std::string& iban) {
        if (!init) return this;
        if (!data.contains("bankAccount") || !data["bankAccount"].is_object()) return this;

        fieldData["Iban"] = localVault.crypto.Encrypt(iban, itemEncKey, itemMacKey);
        data["bankAccount"]["iban"] = localVault.crypto.Encrypt(iban, itemEncKey, itemMacKey);

        OPENSSL_cleanse(iban.data(), iban.size());
        iban.clear();
        return this;
    }

    BankAccountItem* BankAccountItem::SetBankContactPhone(std::string& bankContactPhone) {
        if (!init) return this;
        if (!data.contains("bankAccount") || !data["bankAccount"].is_object()) return this;

        fieldData["BankContactPhone"] = localVault.crypto.Encrypt(bankContactPhone, itemEncKey, itemMacKey);
        data["bankAccount"]["bankContactPhone"] = localVault.crypto.Encrypt(bankContactPhone, itemEncKey, itemMacKey);

        OPENSSL_cleanse(bankContactPhone.data(), bankContactPhone.size());
        bankContactPhone.clear();
        return this;
    }

    BankAccountItem* BankAccountItem::GetBankName(std::string& bankName) {
        if (!init) return this;
        if (!data["bankAccount"].is_object()) return this;
        if (!data["bankAccount"].contains("bankName")) return this;
        if (!data["bankAccount"]["bankName"].is_string()) return this;

        bankName = localVault.crypto.DecryptAsStr(data["bankAccount"]["bankName"], itemEncKey, itemMacKey);

        return this;
    }

    BankAccountItem* BankAccountItem::GetNameOnAccount(std::string& nameOnAccount) {
        if (!init) return this;
        if (!data["bankAccount"].is_object()) return this;
        if (!data["bankAccount"].contains("nameOnAccount")) return this;
        if (!data["bankAccount"]["nameOnAccount"].is_string()) return this;

        nameOnAccount = localVault.crypto.DecryptAsStr(data["bankAccount"]["nameOnAccount"], itemEncKey, itemMacKey);

        return this;
    }

    BankAccountItem* BankAccountItem::GetAccountType(std::string& accountType) {
        if (!init) return this;
        if (!data["bankAccount"].is_object()) return this;
        if (!data["bankAccount"].contains("accountType")) return this;
        if (!data["bankAccount"]["accountType"].is_string()) return this;

        accountType = localVault.crypto.DecryptAsStr(data["bankAccount"]["accountType"], itemEncKey, itemMacKey);

        return this;
    }

    BankAccountItem* BankAccountItem::GetAccountNumber(std::string& accountNumber) {
        if (!init) return this;
        if (!data["bankAccount"].is_object()) return this;
        if (!data["bankAccount"].contains("accountNumber")) return this;
        if (!data["bankAccount"]["accountNumber"].is_string()) return this;

        accountNumber = localVault.crypto.DecryptAsStr(data["bankAccount"]["accountNumber"], itemEncKey, itemMacKey);

        return this;
    }

    BankAccountItem* BankAccountItem::GetRoutingNumber(std::string& routingNumber) {
        if (!init) return this;
        if (!data["bankAccount"].is_object()) return this;
        if (!data["bankAccount"].contains("routingNumber")) return this;
        if (!data["bankAccount"]["routingNumber"].is_string()) return this;

        routingNumber = localVault.crypto.DecryptAsStr(data["bankAccount"]["routingNumber"], itemEncKey, itemMacKey);

        return this;
    }

    BankAccountItem* BankAccountItem::GetBranchNumber(std::string& branchNumber) {
        if (!init) return this;
        if (!data["bankAccount"].is_object()) return this;
        if (!data["bankAccount"].contains("branchNumber")) return this;
        if (!data["bankAccount"]["branchNumber"].is_string()) return this;

        branchNumber = localVault.crypto.DecryptAsStr(data["bankAccount"]["branchNumber"], itemEncKey, itemMacKey);

        return this;
    }

    BankAccountItem* BankAccountItem::GetPin(std::string& pin) {
        if (!init) return this;
        if (!data["bankAccount"].is_object()) return this;
        if (!data["bankAccount"].contains("pin")) return this;
        if (!data["bankAccount"]["pin"].is_string()) return this;

        pin = localVault.crypto.DecryptAsStr(data["bankAccount"]["pin"], itemEncKey, itemMacKey);

        return this;
    }

    BankAccountItem* BankAccountItem::GetSwiftCode(std::string& swiftCode) {
        if (!init) return this;
        if (!data["bankAccount"].is_object()) return this;
        if (!data["bankAccount"].contains("swiftCode")) return this;
        if (!data["bankAccount"]["swiftCode"].is_string()) return this;

        swiftCode = localVault.crypto.DecryptAsStr(data["bankAccount"]["swiftCode"], itemEncKey, itemMacKey);

        return this;
    }

    BankAccountItem* BankAccountItem::GetIBAN(std::string& iban) {
        if (!init) return this;
        if (!data["bankAccount"].is_object()) return this;
        if (!data["bankAccount"].contains("iban")) return this;
        if (!data["bankAccount"]["iban"].is_string()) return this;

        iban = localVault.crypto.DecryptAsStr(data["bankAccount"]["iban"], itemEncKey, itemMacKey);

        return this;
    }

    BankAccountItem* BankAccountItem::GetBankContactPhone(std::string& bankContactPhone) {
        if (!init) return this;
        if (!data["bankAccount"].is_object()) return this;
        if (!data["bankAccount"].contains("bankContactPhone")) return this;
        if (!data["bankAccount"]["bankContactPhone"].is_string()) return this;

        bankContactPhone = localVault.crypto.DecryptAsStr(data["bankAccount"]["bankContactPhone"], itemEncKey, itemMacKey);

        return this;
    }

    BankAccountItem* BankAccountItem::GetType(CipherType& val) {
        val = CipherType::BankAccount;
        return this;
    }
}