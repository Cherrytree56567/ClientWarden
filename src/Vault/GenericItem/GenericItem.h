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
    class GenericItem {
    public:
        GenericItem(Vault& vault, std::string uuid); // Existing Item
        ~GenericItem();

        GenericItem& SetName(std::string& name);
        GenericItem& SetNotes(std::string& notes);
        GenericItem& SetFolder(std::string folder);
        GenericItem& RemoveFolder();
        GenericItem& AddField(CustomFieldType field, std::string& name, std::string& value);
        GenericItem& RemoveField(std::string& name);

        GenericItem& GetName(std::string& name);
        GenericItem& GetNotes(std::string& notes);
        GenericItem& GetFolder(std::string& folder);
        GenericItem& GetFields(std::vector<std::tuple<CustomFieldType, std::string, std::string>>& value);
        GenericItem& GetId(std::string& value);
        
        GenericItem& AddAttachment(std::string& name, std::string& content, std::string& id, std::function<void(float)> onProgress = nullptr);
        GenericItem& GetAttachmentIDs(std::vector<std::string>& ids);
        GenericItem& GetAttachmentName(std::string id, std::string& name);
        GenericItem& GetAttachment(std::string id, std::string& content, std::function<void(float)> onProgress = nullptr);
        GenericItem& RemoveAttachment(std::string id);
        
        GenericItem& SetFavorite(bool val);
        GenericItem& SetReprompt(bool val);
        GenericItem& GetFavorite(bool& val);
        GenericItem& GetReprompt(bool& val);

        void Commit();
        void Delete();
        void Bin();
        void UnBin();
        void Close();
    private:
        /*
         * Secret Data
        */
        std::vector<uint8_t> itemEncKey;
        std::vector<uint8_t> itemMacKey;

        bool isBeingCreated;
        bool init;
        nlohmann::json data;
        nlohmann::json fieldData;
        Vault& localVault;
        inline static std::shared_ptr<spdlog::logger> logger = nullptr;
    };
}