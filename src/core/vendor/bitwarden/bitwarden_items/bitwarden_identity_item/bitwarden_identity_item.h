#pragma once
#include "items/generic_item_impl.h"
#include "../bitwarden_generic_item.h"

namespace clientwarden::vendor::bitwarden {
    class BitwardenIdentityItem 
        : public GenericItemImpl<BitwardenGenericItem, BitwardenIdentityItem> {
    public:
        BitwardenIdentityItem(Vault& vault, ItemId id, bool item_creation);

        BitwardenIdentityItem* setAddress1(const Botan::secure_vector<uint8_t>& address_1);
        BitwardenIdentityItem* setAddress2(const Botan::secure_vector<uint8_t>& address_2);
        BitwardenIdentityItem* setAddress3(const Botan::secure_vector<uint8_t>& address_3);
        BitwardenIdentityItem* setCity(const Botan::secure_vector<uint8_t>& city);
        BitwardenIdentityItem* setCompany(const Botan::secure_vector<uint8_t>& company);
        BitwardenIdentityItem* setCountry(const Botan::secure_vector<uint8_t>& country);
        BitwardenIdentityItem* setEmail(const Botan::secure_vector<uint8_t>& email);
        BitwardenIdentityItem* setFirstName(const Botan::secure_vector<uint8_t>& first_name);
        BitwardenIdentityItem* setLastName(const Botan::secure_vector<uint8_t>& last_name);
        BitwardenIdentityItem* setLicenceNumber(const Botan::secure_vector<uint8_t>& license_number);
        BitwardenIdentityItem* setMiddleName(const Botan::secure_vector<uint8_t>& middle_name);
        BitwardenIdentityItem* setPassportNumber(const Botan::secure_vector<uint8_t>& passport_number);
        BitwardenIdentityItem* setPhone(const Botan::secure_vector<uint8_t>& phone);
        BitwardenIdentityItem* setPostalCode(const Botan::secure_vector<uint8_t>& postal_code);
        BitwardenIdentityItem* setSSN(const Botan::secure_vector<uint8_t>& ssn);
        BitwardenIdentityItem* setState(const Botan::secure_vector<uint8_t>& state);
        BitwardenIdentityItem* setTitle(const Botan::secure_vector<uint8_t>& title);
        BitwardenIdentityItem* setUsername(const Botan::secure_vector<uint8_t>& username);

        BitwardenIdentityItem* duplicate(ItemId& id);

        BitwardenIdentityItem* getAddress1(Botan::secure_vector<uint8_t>& address_1);
        BitwardenIdentityItem* getAddress2(Botan::secure_vector<uint8_t>& address_2);
        BitwardenIdentityItem* getAddress3(Botan::secure_vector<uint8_t>& address_3);
        BitwardenIdentityItem* getCity(Botan::secure_vector<uint8_t>& city);
        BitwardenIdentityItem* getCompany(Botan::secure_vector<uint8_t>& company);
        BitwardenIdentityItem* getCountry(Botan::secure_vector<uint8_t>& country);
        BitwardenIdentityItem* getEmail(Botan::secure_vector<uint8_t>& email);
        BitwardenIdentityItem* getFirstName(Botan::secure_vector<uint8_t>& first_name);
        BitwardenIdentityItem* getLastName(Botan::secure_vector<uint8_t>& last_name);
        BitwardenIdentityItem* getLicenceNumber(Botan::secure_vector<uint8_t>& license_number);
        BitwardenIdentityItem* getMiddleName(Botan::secure_vector<uint8_t>& middle_name);
        BitwardenIdentityItem* getPassportNumber(Botan::secure_vector<uint8_t>& passport_number);
        BitwardenIdentityItem* getPhone(Botan::secure_vector<uint8_t>& phone);
        BitwardenIdentityItem* getPostalCode(Botan::secure_vector<uint8_t>& postal_code);
        BitwardenIdentityItem* getSSN(Botan::secure_vector<uint8_t>& ssn);
        BitwardenIdentityItem* getState(Botan::secure_vector<uint8_t>& state);
        BitwardenIdentityItem* getTitle(Botan::secure_vector<uint8_t>& title);
        BitwardenIdentityItem* getUsername(Botan::secure_vector<uint8_t>& username);
        BitwardenIdentityItem* getType(ItemType& val);
    };
}