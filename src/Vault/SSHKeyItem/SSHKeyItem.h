#pragma once
#include <string>
#include <vector>
#include <nlohmann/json.hpp>
#include "../CommonVault.h"
#include "../VaultUtils/VaultUtils.h"
#include "../Vault.h"

namespace ClientWarden::Vault {
    class SSHKeyItem {
    public:
        SSHKeyItem(Vault& vault, std::string uuid); // Existing Item
        SSHKeyItem(Vault& vault); // New Item
        ~SSHKeyItem();

        SSHKeyItem& SetName(std::string& name);
        SSHKeyItem& SetFingerprint(std::string& fingerprint);
        SSHKeyItem& SetPrivateKey(std::string& privateKey);
        SSHKeyItem& SetPublicKey(std::string& publicKey);
        SSHKeyItem& SetNotes(std::string& notes);
        SSHKeyItem& SetFolder(std::string folder);
        SSHKeyItem& RemoveFolder();
        SSHKeyItem& AddField(CustomFieldType field, std::string& name, std::string& value);
        SSHKeyItem& RemoveField(std::string& name);
        SSHKeyItem& SetFavorite(bool val);
        SSHKeyItem& SetReprompt(bool val);

        SSHKeyItem& GetName(std::string& name);
        SSHKeyItem& GetFingerprint(std::string& fingerprint);
        SSHKeyItem& GetPrivateKey(std::string& privateKey);
        SSHKeyItem& GetPublicKey(std::string& publicKey);
        SSHKeyItem& GetNotes(std::string& notes);
        SSHKeyItem& GetFolder(std::string& folder);
        SSHKeyItem& GetFields(std::vector<std::tuple<CustomFieldType, std::string, std::string>>& value);
        SSHKeyItem& GetFavorite(bool& val);
        SSHKeyItem& GetReprompt(bool& val);

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
        inline static std::shared_ptr<spdlog::logger> logger = nullptr;
    };
}