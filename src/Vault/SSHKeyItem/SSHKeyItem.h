#pragma once
#include <string>
#include <vector>
#include <nlohmann/json.hpp>
#include "../CommonVault.h"
#include "../VaultUtils/VaultUtils.h"
#include "../Vault.h"
#include "../GenericItem/GenericItem.h"

namespace ClientWarden {
    class SSHKeyItem : public GenericItem {
    public:
        SSHKeyItem(Vault& vault, std::string uuid); // Existing Item
        SSHKeyItem(Vault& vault); // New Item

        SSHKeyItem* SetName(std::string& name) override;
        SSHKeyItem* SetFingerprint(std::string& fingerprint);
        SSHKeyItem* SetPrivateKey(std::string& privateKey);
        SSHKeyItem* SetPublicKey(std::string& publicKey);
        SSHKeyItem* SetNotes(std::string& notes) override;
        SSHKeyItem* SetFolder(std::string folder) override;
        SSHKeyItem* RemoveFolder() override;
        SSHKeyItem* AddField(CustomFieldType field, std::string& name, std::string& value) override;
        SSHKeyItem* RemoveField(std::string& name) override;
        SSHKeyItem* ClearFields() override;
        SSHKeyItem* SetFavorite(bool val) override;
        SSHKeyItem* SetReprompt(bool val) override;

        SSHKeyItem* Duplicate(std::string& id);

        SSHKeyItem* GetName(std::string& name) override;
        SSHKeyItem* GetFingerprint(std::string& fingerprint);
        SSHKeyItem* GetPrivateKey(std::string& privateKey);
        SSHKeyItem* GetPublicKey(std::string& publicKey);
        SSHKeyItem* GetNotes(std::string& notes) override;
        SSHKeyItem* GetFolder(std::string& folder) override;
        SSHKeyItem* GetFields(std::vector<std::tuple<CustomFieldType, std::string, std::string>>& value) override;
        SSHKeyItem* GetFavorite(bool& val) override;
        SSHKeyItem* GetReprompt(bool& val) override;
        SSHKeyItem* GetId(std::string& value) override;
        SSHKeyItem* GetType(CipherType& val) override;
        SSHKeyItem* GetCreation(std::string& value) override;
        SSHKeyItem* GetModification(std::string& value) override;
        SSHKeyItem* GetDeletion(std::string& value) override;
        
        SSHKeyItem* AddAttachment(std::string& name, std::string& content, std::string& id, std::function<void(float)> onProgress = nullptr) override;
        SSHKeyItem* GetAttachmentIDs(std::vector<std::string>& ids) override;
        SSHKeyItem* GetAttachmentName(std::string id, std::string& name) override;
        SSHKeyItem* GetAttachment(std::string id, std::string& content, std::function<void(float)> onProgress = nullptr) override;
        SSHKeyItem* RemoveAttachment(std::string id) override;
    private:
        inline static std::shared_ptr<spdlog::logger> l_logger = nullptr;
    };
}