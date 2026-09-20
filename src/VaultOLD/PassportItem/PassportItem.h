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
     * https://github.com/bitwarden/clients/blob/main/libs/common/src/vault/models/domain/passport.ts
    */
    class PassportItem : public GenericItemImpl<PassportItem> {
    public:
        PassportItem(Vault& vault, std::string uuid); // Existing Item
        PassportItem(Vault& vault); // New Item

        PassportItem* SetSurname(std::string& surname);
        PassportItem* SetGivenName(std::string& givenName);
        PassportItem* SetDateOfBirth(std::string& dateOfBirth);
        PassportItem* SetSex(std::string& sex);
        PassportItem* SetBirthPlace(std::string& birthPlace);
        PassportItem* SetNationality(std::string& nationality);
        PassportItem* SetIssuingCountry(std::string& issuingCountry);
        PassportItem* SetPassportNumber(std::string& passportNumber);
        PassportItem* SetPassportType(std::string& passportType);
        PassportItem* SetNationalIdentificationNumber(std::string& nationalIdentificationNumber);
        PassportItem* SetIssuingAuthority(std::string& issuingAuthority);
        PassportItem* SetIssueDate(std::string& issueDate);
        PassportItem* SetExpirationDate(std::string& expirationDate);

        PassportItem* Duplicate(std::string& id);

        PassportItem* GetSurname(std::string& surname);
        PassportItem* GetGivenName(std::string& givenName);
        PassportItem* GetDateOfBirth(std::string& dateOfBirth);
        PassportItem* GetSex(std::string& sex);
        PassportItem* GetBirthPlace(std::string& birthPlace);
        PassportItem* GetNationality(std::string& nationality);
        PassportItem* GetIssuingCountry(std::string& issuingCountry);
        PassportItem* GetPassportNumber(std::string& passportNumber);
        PassportItem* GetPassportType(std::string& passportType);
        PassportItem* GetNationalIdentificationNumber(std::string& nationalIdentificationNumber);
        PassportItem* GetIssuingAuthority(std::string& issuingAuthority);
        PassportItem* GetIssueDate(std::string& issueDate);
        PassportItem* GetExpirationDate(std::string& expirationDate);
        PassportItem* GetType(CipherType& val);
    };
}