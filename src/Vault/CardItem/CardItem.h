#pragma once
#include <string>
#include <vector>
#include <nlohmann/json.hpp>
#include "../CommonVault.h"
#include "../VaultUtils/VaultUtils.h"
#include "../Vault.h"

namespace ClientWarden::Vault {
    class CardItem {
    public:
        CardItem(Vault& vault, std::string uuid); // Existing Item
        CardItem(Vault& vault); // New Item
        ~CardItem();

        CardItem& SetName(std::string& name);
        CardItem& SetBrand(std::string& brand);
        CardItem& SetCardholderName(std::string& cardholderName);
        CardItem& SetCode(std::string& code);
        CardItem& SetExpMonth(std::string& expMonth);
        CardItem& SetExpYear(std::string& expYear);
        CardItem& SetNumber(std::string& number);
        CardItem& SetNotes(std::string& notes);
        CardItem& SetFolder(std::string folder);
        CardItem& RemoveFolder();
        CardItem& AddField(CustomFieldType field, std::string& name, std::string& value);
        CardItem& RemoveField(std::string& name);
        CardItem& SetFavorite(bool val);
        CardItem& SetReprompt(bool val);

        CardItem& GetName(std::string& name);
        CardItem& GetBrand(std::string& brand);
        CardItem& GetCardholderName(std::string& cardholderName);
        CardItem& GetCode(std::string& code);
        CardItem& GetExpMonth(std::string& expMonth);
        CardItem& GetExpYear(std::string& expYear);
        CardItem& GetNumber(std::string& number);
        CardItem& GetNotes(std::string& notes);
        CardItem& GetFolder(std::string& folder);
        CardItem& GetFields(std::vector<std::tuple<CustomFieldType, std::string, std::string>>& value);
        CardItem& GetFavorite(bool& val);
        CardItem& GetReprompt(bool& val);

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
    };
}