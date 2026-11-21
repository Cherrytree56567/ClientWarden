#pragma once
#include "items/generic_item_impl.h"
#include "../bitwarden_generic_item.h"

namespace clientwarden::vendor::bitwarden {
    class BitwardenCardItem 
        : public GenericItemImpl<BitwardenGenericItem, BitwardenCardItem> {
    public:
        BitwardenCardItem(Vault& vault, ItemId id, bool item_creation);

        BitwardenCardItem* setBrand(const Botan::secure_vector<uint8_t>& brand);
        BitwardenCardItem* setCardholderName(const Botan::secure_vector<uint8_t>& cardholder_name);
        BitwardenCardItem* setCode(const Botan::secure_vector<uint8_t>& code);
        BitwardenCardItem* setExpMonth(const Botan::secure_vector<uint8_t>& exp_month);
        BitwardenCardItem* setExpYear(const Botan::secure_vector<uint8_t>& exp_year);
        BitwardenCardItem* setNumber(const Botan::secure_vector<uint8_t>& number);

        BitwardenCardItem* duplicate(Botan::secure_vector<uint8_t>& id);

        BitwardenCardItem* getBrand(Botan::secure_vector<uint8_t>& brand);
        BitwardenCardItem* getCardholderName(Botan::secure_vector<uint8_t>& cardholder_name);
        BitwardenCardItem* getCode(Botan::secure_vector<uint8_t>& code);
        BitwardenCardItem* getExpMonth(Botan::secure_vector<uint8_t>& exp_month);
        BitwardenCardItem* getExpYear(Botan::secure_vector<uint8_t>& exp_year);
        BitwardenCardItem* getNumber(Botan::secure_vector<uint8_t>& number);
        BitwardenCardItem* getType(ItemType& val);
    };
}