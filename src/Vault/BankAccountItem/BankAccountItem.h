#pragma once
#include <algorithm>
#include <botan/hash.h>
#include <botan/otp.h>
#include <boost/url.hpp>
#include <botan/base32.h>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "../GenericItem/GenericItemImpl.h"

#include "Clientwarden.h"

namespace ClientWarden {
    /*
     * From Bitwarden Clients:
     * https://github.com/bitwarden/clients/blob/main/libs/common/src/vault/models/domain/bank-account.ts
    */
    class BankAccountItem : public GenericItemImpl<BankAccountItem> {
    public:
        BankAccountItem(Vault& vault, std::string uuid); // Existing Item
        BankAccountItem(Vault& vault); // New Item

        BankAccountItem* SetBankName(std::string& bankName);
        BankAccountItem* SetNameOnAccount(std::string& nameOnAccount);
        BankAccountItem* SetAccountType(std::string& accountType);
        BankAccountItem* SetAccountNumber(std::string& accountNumber);
        BankAccountItem* SetRoutingNumber(std::string& routingNumber);
        BankAccountItem* SetBranchNumber(std::string& branchNumber);
        BankAccountItem* SetPin(std::string& pin);
        BankAccountItem* SetSwiftCode(std::string& swiftCode);
        BankAccountItem* SetIBAN(std::string& iban);
        BankAccountItem* SetBankContactPhone(std::string& bankContactPhone);

        BankAccountItem* Duplicate(std::string& id);

        BankAccountItem* GetBankName(std::string& bankName);
        BankAccountItem* GetNameOnAccount(std::string& nameOnAccount);
        BankAccountItem* GetAccountType(std::string& accountType);
        BankAccountItem* GetAccountNumber(std::string& accountNumber);
        BankAccountItem* GetRoutingNumber(std::string& routingNumber);
        BankAccountItem* GetBranchNumber(std::string& branchNumber);
        BankAccountItem* GetPin(std::string& pin);
        BankAccountItem* GetSwiftCode(std::string& swiftCode);
        BankAccountItem* GetIBAN(std::string& iban);
        BankAccountItem* GetBankContactPhone(std::string& bankContactPhone);
        BankAccountItem* GetType(CipherType& val);
    };
}