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

namespace ClientWarden {
    class GenericItem {
    public:
        GenericItem(Vault& vault, std::string uuid); // Existing Item
        GenericItem(Vault& vault); // New Item (need to be initialised by a derived class)
        ~GenericItem();

        virtual GenericItem* SetName(std::string& name);
        virtual GenericItem* SetNotes(std::string& notes);
        virtual GenericItem* SetFolder(std::string folder);
        virtual GenericItem* RemoveFolder();
        virtual GenericItem* AddField(CustomFieldType field, std::string& name, std::string& value);
        virtual GenericItem* RemoveField(std::string& name);

        virtual GenericItem* GetName(std::string& name);
        virtual GenericItem* GetNotes(std::string& notes);
        virtual GenericItem* GetFolder(std::string& folder);
        virtual GenericItem* GetFields(std::vector<std::tuple<CustomFieldType, std::string, std::string>>& value);
        virtual GenericItem* GetId(std::string& value);
        virtual GenericItem* GetCreation(std::string& value);
        virtual GenericItem* GetModification(std::string& value);
        virtual GenericItem* GetDeletion(std::string& value);
        
        virtual GenericItem* AddAttachment(std::string& name, std::string& content, std::string& id, std::function<void(float)> onProgress = nullptr);
        virtual GenericItem* GetAttachmentIDs(std::vector<std::string>& ids);
        virtual GenericItem* GetAttachmentName(std::string id, std::string& name);
        virtual GenericItem* GetAttachment(std::string id, std::string& content, std::function<void(float)> onProgress = nullptr);
        virtual GenericItem* RemoveAttachment(std::string id);
        
        virtual GenericItem* SetFavorite(bool val);
        virtual GenericItem* SetReprompt(bool val);
        virtual GenericItem* GetFavorite(bool& val);
        virtual GenericItem* GetReprompt(bool& val);
        virtual GenericItem* GetType(CipherType& val);

        void Commit();
        void Delete();
        void Bin();
        void UnBin();
        void Close();
    protected:
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