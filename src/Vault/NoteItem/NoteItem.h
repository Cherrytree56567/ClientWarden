#pragma once
#include <string>
#include <vector>
#include <nlohmann/json.hpp>
#include "../CommonVault.h"
#include "../VaultUtils/VaultUtils.h"
#include "../Vault.h"

namespace ClientWarden::Vault {
    class NoteItem {
    public:
        NoteItem(Vault& vault, std::string uuid); // Existing Item
        NoteItem(Vault& vault); // New Item
        ~NoteItem();

        NoteItem& SetName(std::string& name);
        NoteItem& SetNotes(std::string& notes);
        NoteItem& SetFolder(std::string folder);
        NoteItem& RemoveFolder();
        NoteItem& AddField(CustomFieldType field, std::string& name, std::string& value);
        NoteItem& RemoveField(std::string& name);

        NoteItem& Duplicate(std::string& id);

        NoteItem& GetName(std::string& name);
        NoteItem& GetNotes(std::string& notes);
        NoteItem& GetFolder(std::string& folder);
        NoteItem& GetFields(std::vector<std::tuple<CustomFieldType, std::string, std::string>>& value);
        NoteItem& GetId(std::string& value);
        
        NoteItem& AddAttachment(std::string& name, std::string& content);
        NoteItem& GetAttachmentIDs(std::vector<std::string>& ids);
        NoteItem& GetAttachmentName(std::string id, std::string& name);
        NoteItem& GetAttachment(std::string id, std::string& content);
        NoteItem& RemoveAttachment(std::string id);
        
        NoteItem& SetFavorite(bool val);
        NoteItem& SetReprompt(bool val);
        NoteItem& GetFavorite(bool& val);
        NoteItem& GetReprompt(bool& val);

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