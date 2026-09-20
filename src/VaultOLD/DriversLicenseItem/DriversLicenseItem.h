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
     * https://github.com/bitwarden/clients/blob/main/libs/common/src/vault/models/domain/drivers-license.ts
    */
    class DriversLicenseItem : public GenericItemImpl<DriversLicenseItem> {
    public:
        DriversLicenseItem(Vault& vault, std::string uuid); // Existing Item
        DriversLicenseItem(Vault& vault); // New Item

        DriversLicenseItem* SetFirstName(std::string& firstName);
        DriversLicenseItem* SetMiddleName(std::string& middleName);
        DriversLicenseItem* SetLastName(std::string& lastName);
        DriversLicenseItem* SetDateOfBirth(std::string& dateOfBirth);
        DriversLicenseItem* SetLicenseNumber(std::string& licenseNumber);
        DriversLicenseItem* SetIssuingCountry(std::string& issuingCountry);
        DriversLicenseItem* SetIssuingState(std::string& issuingState);
        DriversLicenseItem* SetIssueDate(std::string& issueDate);
        DriversLicenseItem* SetExpirationDate(std::string& expirationDate);
        DriversLicenseItem* SetIssuingAuthority(std::string& issuingAuthority);
        DriversLicenseItem* SetLicenseClass(std::string& licenseClass);

        DriversLicenseItem* Duplicate(std::string& id);

        DriversLicenseItem* GetFirstName(std::string& firstName);
        DriversLicenseItem* GetMiddleName(std::string& middleName);
        DriversLicenseItem* GetLastName(std::string& lastName);
        DriversLicenseItem* GetDateOfBirth(std::string& dateOfBirth);
        DriversLicenseItem* GetLicenseNumber(std::string& licenseNumber);
        DriversLicenseItem* GetIssuingCountry(std::string& issuingCountry);
        DriversLicenseItem* GetIssuingState(std::string& issuingState);
        DriversLicenseItem* GetIssueDate(std::string& issueDate);
        DriversLicenseItem* GetExpirationDate(std::string& expirationDate);
        DriversLicenseItem* GetIssuingAuthority(std::string& issuingAuthority);
        DriversLicenseItem* GetLicenseClass(std::string& licenseClass);
        DriversLicenseItem* GetType(CipherType& val);
    };
}