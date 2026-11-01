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
    struct TOTPCode {
        std::string code;
        std::time_t remaining;
        int period;
    };

    class LoginItem : public GenericItemImpl<LoginItem> {
    public:
        LoginItem(Vault& vault, std::string uuid); // Existing Item
        LoginItem(Vault& vault); // New Item

        LoginItem* SetUsername(std::string& username);
        LoginItem* SetPassword(std::string& password);
        LoginItem* SetTotp(std::string& totp);
        //LoginItem* SetPasskeyCounter(std::time_t& value);
        LoginItem* AddWebsite(std::string& website);
        LoginItem* RemoveWebsite(std::string& website);

        LoginItem* Duplicate(std::string& id);

        LoginItem* GetUsername(std::string& username);
        LoginItem* GetPassword(std::string& password);
        LoginItem* GetTotp(TOTPCode& totp);
        LoginItem* GetTotpSecret(std::string& totp);
        LoginItem* GetWebsites(std::vector<std::string>& website);
        LoginItem* GetPasswordHistory(std::vector<std::pair<std::time_t, std::string>>& value);
        LoginItem* GetPasskeyCreationDate(std::vector<std::time_t>& value);
        /*LoginItem* GetPasskeyPartyId(std::time_t& value);
        LoginItem* GetPasskeyUsername(std::time_t& value);
        LoginItem* GetPasskeyUserhandle(std::time_t& value);
        LoginItem* GetPasskeyPrivKey(std::time_t& value);
        LoginItem* GetPasskeyAlgo(std::time_t& value);
        LoginItem* GetPasskeyCurve(std::time_t& value);
        LoginItem* GetPasskeyCredId(std::time_t& value);
        LoginItem* GetPasskeyCounter(std::time_t& value);*/
        LoginItem* GetType(CipherType& val);
    };
}