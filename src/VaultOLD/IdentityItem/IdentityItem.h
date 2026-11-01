#pragma once
#include <string>
#include <vector>
#include <nlohmann/json.hpp>
#include "../GenericItem/GenericItemImpl.h"

#include "Clientwarden.h"

namespace ClientWarden {
    class IdentityItem : public GenericItemImpl<IdentityItem> {
    public:
        IdentityItem(Vault& vault, std::string uuid); // Existing Item
        IdentityItem(Vault& vault); // New Item

        IdentityItem* SetAddress1(std::string& address1);
        IdentityItem* SetAddress2(std::string& address2);
        IdentityItem* SetAddress3(std::string& address3);
        IdentityItem* SetCity(std::string& city);
        IdentityItem* SetCompany(std::string& company);
        IdentityItem* SetCountry(std::string& country);
        IdentityItem* SetEmail(std::string& email);
        IdentityItem* SetFirstName(std::string& firstName);
        IdentityItem* SetLastName(std::string& lastName);
        IdentityItem* SetLicenceNumber(std::string& licenseNumber);
        IdentityItem* SetMiddleName(std::string& middleName);
        IdentityItem* SetPassportNumber(std::string& passportNumber);
        IdentityItem* SetPhone(std::string& phone);
        IdentityItem* SetPostalCode(std::string& postalCode);
        IdentityItem* SetSSN(std::string& ssn);
        IdentityItem* SetState(std::string& state);
        IdentityItem* SetTitle(std::string& title);
        IdentityItem* SetUsername(std::string& username);

        IdentityItem* Duplicate(std::string& id);

        IdentityItem* GetAddress1(std::string& address1);
        IdentityItem* GetAddress2(std::string& address2);
        IdentityItem* GetAddress3(std::string& address3);
        IdentityItem* GetCity(std::string& city);
        IdentityItem* GetCompany(std::string& company);
        IdentityItem* GetCountry(std::string& country);
        IdentityItem* GetEmail(std::string& email);
        IdentityItem* GetFirstName(std::string& firstName);
        IdentityItem* GetLastName(std::string& lastName);
        IdentityItem* GetLicenceNumber(std::string& licenseNumber);
        IdentityItem* GetMiddleName(std::string& middleName);
        IdentityItem* GetPassportNumber(std::string& passportNumber);
        IdentityItem* GetPhone(std::string& phone);
        IdentityItem* GetPostalCode(std::string& postalCode);
        IdentityItem* GetSSN(std::string& ssn);
        IdentityItem* GetState(std::string& state);
        IdentityItem* GetTitle(std::string& title);
        IdentityItem* GetUsername(std::string& username);
        IdentityItem* GetType(CipherType& val);
    };
}