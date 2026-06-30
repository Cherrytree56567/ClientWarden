#pragma once
#include <algorithm>
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
#include "../GenericItem/GenericItem.h"

namespace ClientWarden {
    struct TOTPCode {
        std::string code;
        std::time_t remaining;
    };

    class LoginItem : public GenericItem {
    public:
        LoginItem(Vault& vault, std::string uuid); // Existing Item
        LoginItem(Vault& vault); // New Item

        LoginItem* SetName(std::string& name) override;
        LoginItem* SetUsername(std::string& username);
        LoginItem* SetPassword(std::string& password);
        LoginItem* SetTotp(std::string& totp);
        LoginItem* SetNotes(std::string& notes) override;
        LoginItem* SetFolder(std::string folder) override;
        //LoginItem* SetPasskeyCounter(std::time_t& value);
        LoginItem* RemoveFolder() override;
        LoginItem* AddWebsite(std::string& website);
        LoginItem* RemoveWebsite(std::string& website);
        LoginItem* AddField(CustomFieldType field, std::string& name, std::string& value) override;
        LoginItem* RemoveField(std::string& name) override;

        LoginItem* Duplicate(std::string& id);

        LoginItem* GetName(std::string& name) override;
        LoginItem* GetUsername(std::string& username);
        LoginItem* GetPassword(std::string& password);
        LoginItem* GetTotp(TOTPCode& totp);
        LoginItem* GetTotpSecret(std::string& totp);
        LoginItem* GetNotes(std::string& notes) override;
        LoginItem* GetFolder(std::string& folder) override;
        LoginItem* GetWebsites(std::vector<std::string>& website);
        LoginItem* GetFields(std::vector<std::tuple<CustomFieldType, std::string, std::string>>& value) override;
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
        LoginItem* GetId(std::string& value) override;
        
        LoginItem* AddAttachment(std::string& name, std::string& content, std::string& id, std::function<void(float)> onProgress = nullptr) override;
        LoginItem* GetAttachmentIDs(std::vector<std::string>& ids) override;
        LoginItem* GetAttachmentName(std::string id, std::string& name) override;
        LoginItem* GetAttachment(std::string id, std::string& content, std::function<void(float)> onProgress = nullptr) override;
        LoginItem* RemoveAttachment(std::string id) override;
        
        LoginItem* SetFavorite(bool val) override;
        LoginItem* SetReprompt(bool val) override;
        LoginItem* GetFavorite(bool& val) override;
        LoginItem* GetReprompt(bool& val) override;
    private:
        inline static std::shared_ptr<spdlog::logger> l_logger = nullptr;
    };
}