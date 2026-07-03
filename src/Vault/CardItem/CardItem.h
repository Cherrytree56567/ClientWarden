#pragma once
#include <string>
#include <vector>
#include <nlohmann/json.hpp>
#include "../CommonVault.h"
#include "../VaultUtils/VaultUtils.h"
#include "../Vault.h"
#include "../GenericItem/GenericItem.h"

namespace ClientWarden {
    class CardItem : public GenericItem {
    public:
        CardItem(Vault& vault, std::string uuid); // Existing Item
        CardItem(Vault& vault); // New Item

        CardItem* SetName(std::string& name) override;
        CardItem* SetBrand(std::string& brand);
        CardItem* SetCardholderName(std::string& cardholderName);
        CardItem* SetCode(std::string& code);
        CardItem* SetExpMonth(std::string& expMonth);
        CardItem* SetExpYear(std::string& expYear);
        CardItem* SetNumber(std::string& number);
        CardItem* SetNotes(std::string& notes) override;
        CardItem* SetFolder(std::string folder) override;
        CardItem* RemoveFolder() override;
        CardItem* AddField(CustomFieldType field, std::string& name, std::string& value) override;
        CardItem* RemoveField(std::string& name) override;
        CardItem* SetFavorite(bool val) override;
        CardItem* SetReprompt(bool val) override;

        CardItem* Duplicate(std::string& id);

        /*
         * Secret Data
        */
        CardItem* GetName(std::string& name) override;
        CardItem* GetBrand(std::string& brand);
        CardItem* GetCardholderName(std::string& cardholderName);
        CardItem* GetCode(std::string& code);
        CardItem* GetExpMonth(std::string& expMonth);
        CardItem* GetExpYear(std::string& expYear);
        CardItem* GetNumber(std::string& number);
        CardItem* GetNotes(std::string& notes) override;
        CardItem* GetFolder(std::string& folder) override;
        CardItem* GetFields(std::vector<std::tuple<CustomFieldType, std::string, std::string>>& value) override;
        CardItem* GetFavorite(bool& val) override;
        CardItem* GetReprompt(bool& val) override;
        CardItem* GetId(std::string& value) override;
        CardItem* GetType(CipherType& val) override;
        CardItem* GetCreation(std::string& value) override;
        CardItem* GetModification(std::string& value) override;
        CardItem* GetDeletion(std::string& value) override;
        
        CardItem* AddAttachment(std::string& name, std::string& content, std::string& id, std::function<void(float)> onProgress = nullptr) override;
        CardItem* GetAttachmentIDs(std::vector<std::string>& ids) override;
        CardItem* GetAttachmentName(std::string id, std::string& name) override;
        CardItem* GetAttachment(std::string id, std::string& content, std::function<void(float)> onProgress = nullptr) override;
        CardItem* RemoveAttachment(std::string id) override;
    private:
        inline static std::shared_ptr<spdlog::logger> l_logger = nullptr;
    };
}