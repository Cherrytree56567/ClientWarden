#pragma once
#include <string>
#include <vector>
#include <nlohmann/json.hpp>
#include "../CommonVault.h"
#include "../VaultUtils/VaultUtils.h"
#include "../Vault.h"
#include "../GenericItem/GenericItem.h"

namespace ClientWarden {
    class NoteItem : public GenericItem {
    public:
        NoteItem(Vault& vault, std::string uuid); // Existing Item
        NoteItem(Vault& vault); // New Item

        NoteItem* SetName(std::string& name) override;
        NoteItem* SetNotes(std::string& notes) override;
        NoteItem* SetFolder(std::string folder) override;
        NoteItem* RemoveFolder() override;
        NoteItem* AddField(CustomFieldType field, std::string& name, std::string& value) override;
        NoteItem* RemoveField(std::string& name) override;

        NoteItem* Duplicate(std::string& id);

        NoteItem* GetName(std::string& name) override;
        NoteItem* GetNotes(std::string& notes) override;
        NoteItem* GetFolder(std::string& folder) override;
        NoteItem* GetFields(std::vector<std::tuple<CustomFieldType, std::string, std::string>>& value) override;
        NoteItem* GetId(std::string& value) override;
        
        NoteItem* AddAttachment(std::string& name, std::string& content, std::string& id, std::function<void(float)> onProgress = nullptr) override;
        NoteItem* GetAttachmentIDs(std::vector<std::string>& ids) override;
        NoteItem* GetAttachmentName(std::string id, std::string& name) override;
        NoteItem* GetAttachment(std::string id, std::string& content, std::function<void(float)> onProgress = nullptr) override;
        NoteItem* RemoveAttachment(std::string id) override;
        
        NoteItem* SetFavorite(bool val) override;
        NoteItem* SetReprompt(bool val) override;
        NoteItem* GetFavorite(bool& val) override;
        NoteItem* GetReprompt(bool& val) override;
    private:
        inline static std::shared_ptr<spdlog::logger> l_logger = nullptr;
    };
}