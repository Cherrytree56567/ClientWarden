#pragma once
#include "items/generic_item_impl.h"
#include "../bitwarden_generic_item.h"

namespace clientwarden::vendor::bitwarden {
    class BitwardenLoginItem 
        : public GenericItemImpl<BitwardenGenericItem, BitwardenLoginItem> {
    public:
        BitwardenLoginItem(Vault& vault, ItemId id, bool item_creation);

        BitwardenLoginItem* setUsername(std::string& username);
        BitwardenLoginItem* setPassword(std::string& password);
        BitwardenLoginItem* setTotp(std::string& totp);
        //BitwardenLoginItem* setPasskeyCounter(std::time_t& value);
        BitwardenLoginItem* addWebsite(std::string& website);
        BitwardenLoginItem* removeWebsite(std::string& website);

        BitwardenLoginItem* duplicate(std::string& id);

        BitwardenLoginItem* getUsername(std::string& username);
        BitwardenLoginItem* getPassword(std::string& password);
        BitwardenLoginItem* getTotp(TOTPCode& totp);
        BitwardenLoginItem* getTotpSecret(std::string& totp);
        BitwardenLoginItem* getWebsites(std::vector<std::string>& website);
        BitwardenLoginItem* getPasswordHistory(std::vector<std::pair<std::time_t, std::string>>& value);
        BitwardenLoginItem* getPasskeyCreationDate(std::vector<std::time_t>& value);
        /*BitwardenLoginItem* getPasskeyPartyId(std::time_t& value);
        BitwardenLoginItem* getPasskeyUsername(std::time_t& value);
        BitwardenLoginItem* getPasskeyUserhandle(std::time_t& value);
        BitwardenLoginItem* getPasskeyPrivKey(std::time_t& value);
        BitwardenLoginItem* getPasskeyAlgo(std::time_t& value);
        BitwardenLoginItem* getPasskeyCurve(std::time_t& value);
        BitwardenLoginItem* getPasskeyCredId(std::time_t& value);
        BitwardenLoginItem* getPasskeyCounter(std::time_t& value);*/
        BitwardenLoginItem* getType(CipherType& val);
    };
}