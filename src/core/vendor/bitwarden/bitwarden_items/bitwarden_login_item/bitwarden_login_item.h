#pragma once
#include <algorithm>
#include <botan/otp.h>
#include <boost/url.hpp>
#include "items/generic_item_impl.h"
#include "../bitwarden_generic_item.h"

namespace clientwarden::vendor::bitwarden {
    struct PasswordHistory {
        Timestamp revision_date;
        Botan::secure_vector<uint8_t> password;
    };

    struct TOTPCode {
        Botan::secure_vector<uint8_t> code;
        Timestamp expiry;
        int period;
    };

    class BitwardenLoginItem 
        : public GenericItemImpl<BitwardenGenericItem, BitwardenLoginItem> {
    public:
        BitwardenLoginItem(Vault& vault, ItemId id, bool item_creation);

        BitwardenLoginItem* setUsername(Botan::secure_vector<uint8_t>& username);
        BitwardenLoginItem* setPassword(Botan::secure_vector<uint8_t>& password);
        BitwardenLoginItem* setTotp(Botan::secure_vector<uint8_t>& totp);
        //BitwardenLoginItem* setPasskeyCounter(Timestamp& value);
        BitwardenLoginItem* addWebsite(Botan::secure_vector<uint8_t>& website);
        BitwardenLoginItem* removeWebsite(Botan::secure_vector<uint8_t>& website);

        BitwardenLoginItem* duplicate(ItemId& id);

        BitwardenLoginItem* getUsername(Botan::secure_vector<uint8_t>& username);
        BitwardenLoginItem* getPassword(Botan::secure_vector<uint8_t>& password);
        BitwardenLoginItem* getTotp(TOTPCode& totp);
        BitwardenLoginItem* getTotpSecret(Botan::secure_vector<uint8_t>& totp);
        BitwardenLoginItem* getWebsites(std::vector<Botan::secure_vector<uint8_t>>& website);
        BitwardenLoginItem* getPasswordHistory(std::vector<PasswordHistory>& value);
        BitwardenLoginItem* getPasskeyCreationDate(std::vector<Timestamp>& value);
        /*BitwardenLoginItem* getPasskeyPartyId(Timestamp& value);
        BitwardenLoginItem* getPasskeyUsername(Timestamp& value);
        BitwardenLoginItem* getPasskeyUserhandle(Timestamp& value);
        BitwardenLoginItem* getPasskeyPrivKey(Timestamp& value);
        BitwardenLoginItem* getPasskeyAlgo(Timestamp& value);
        BitwardenLoginItem* getPasskeyCurve(Timestamp& value);
        BitwardenLoginItem* getPasskeyCredId(Timestamp& value);
        BitwardenLoginItem* getPasskeyCounter(Timestamp& value);*/
        BitwardenLoginItem* getType(ItemType& val);
    };
}