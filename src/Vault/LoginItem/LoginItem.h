#pragma once
#include <botan/hash.h>
#include <botan/otp.h>
#include <boost/url.hpp>
#include <botan/base32.h>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "../CommonVault.h"
#include "../VaultUtils/VaultUtils.h"
#include "../Vault.h"

namespace ClientWarden::Vault {
    struct TOTPCode {
        std::string code;
        std::time_t remaining;
    };

    class LoginItem {
    public:
        LoginItem(Vault& vault, std::string uuid); // Existing Item
        LoginItem(Vault& vault); // New Item
        ~LoginItem();

        LoginItem& SetName(std::string& name);
        LoginItem& SetUsername(std::string& username);
        LoginItem& SetPassword(std::string& password);
        LoginItem& SetTotp(std::string& totp);
        LoginItem& SetNotes(std::string& notes);
        LoginItem& SetFolder(std::string folder);
        LoginItem& RemoveFolder();
        LoginItem& AddWebsite(std::string& website);
        LoginItem& RemoveWebsite(std::string& website);
        LoginItem& AddField(CustomFieldType field, std::string& name, std::string& value);
        LoginItem& RemoveField(std::string& name);

        LoginItem& GetName(std::string& name);
        LoginItem& GetUsername(std::string& username);
        LoginItem& GetPassword(std::string& password);
        LoginItem& GetTotp(TOTPCode& totp);
        LoginItem& GetNotes(std::string& notes);
        LoginItem& GetFolder(std::string& folder);
        LoginItem& GetWebsites(std::vector<std::string>& website);
        LoginItem& GetFields(std::vector<std::tuple<CustomFieldType, std::string, std::string>>& value);
        LoginItem& GetPasswordHistory(std::vector<std::pair<std::time_t, std::string>>& value);
        LoginItem& GetPasskeyCreationDate(std::time_t& value);
        
        LoginItem& SetFavorite(bool val);
        LoginItem& SetReprompt(bool val);
        LoginItem& GetFavorite(bool& val);
        LoginItem& GetReprompt(bool& val);

        void Commit();
        void Delete();
        void Bin();
        void Close();
    private:
        bool isBeingCreated;
        bool init;
        nlohmann::json data;
        nlohmann::json fieldData;
        std::vector<uint8_t> itemEncKey;
        std::vector<uint8_t> itemMacKey;
        Vault& localVault;
        std::shared_ptr<spdlog::logger> logger;
    };
}