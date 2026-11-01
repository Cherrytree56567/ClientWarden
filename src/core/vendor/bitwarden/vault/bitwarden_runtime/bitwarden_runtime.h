#pragma once
#include "vault/runtime/runtime.h"

namespace clientwarden::vendor::bitwarden::vault {
    class BitwardenRuntime : public Runtime {
    public:
        explicit BitwardenRuntime(std::shared_ptr<Storage> storage);
        ~BitwardenRuntime() override = default;

        RuntimeError loadVault() override;

        std::expected<nlohmann::json, RuntimeError> getVaultData() override;
        std::expected<nlohmann::json, RuntimeError> getItems() override;

        std::expected<std::vector<ItemId>, RuntimeError> getItemIds() override;
        std::expected<nlohmann::json, RuntimeError> getItem(ItemId uuid) override;
        RuntimeError updateItem(ItemId uuid, nlohmann::json item) override;
        RuntimeError addItem(nlohmann::json item) override;
        RuntimeError removeItem(ItemId uuid) override;

        std::expected<std::vector<ItemId>, RuntimeError> getFolders() override;
        std::expected<nlohmann::json, RuntimeError> getFolder(ItemId uuid) override;
        RuntimeError updateFolder(ItemId uuid, nlohmann::json folder) override;
        RuntimeError addFolder(nlohmann::json folder) override;
        RuntimeError removeFolder(ItemId uuid) override;

        RuntimeError addAttachment(ItemId uuid, nlohmann::json attachment) override;
        RuntimeError updateAttachment(ItemId uuid, ItemId attachment_id, nlohmann::json attachment) override;
        RuntimeError removeAttachment(ItemId uuid, ItemId attachment_id) override;
        std::expected<nlohmann::json, RuntimeError> getAttachment(ItemId uuid, ItemId attachment_id) override;
        std::expected<std::vector<ItemId>, RuntimeError> getAttachmentIds(ItemId uuid) override;

        RuntimeError record(PendingChange change) override;
        RuntimeError removeRecord(Entity entity) override;
        std::expected<PendingChange, RuntimeError> getRecord(Entity entity) override;
        std::expected<bool, RuntimeError> recordExists(Entity entity) override;
        std::expected<std::vector<PendingChange>, RuntimeError> getAllRecords(
            ChangeType type = ChangeType::Unknown) override;

        std::expected<Profile, RuntimeError> getProfile() override;
        std::expected<nlohmann::json, RuntimeError> getVaultInfo() override;
        
        std::expected<Botan::secure_vector<uint8_t>, RuntimeError> getVersion() override;
        RuntimeError storeVersion(Botan::secure_vector<uint8_t> version) override;

        Vendor getVendor() override;
    private:
        std::atomic<bool> m_init = false;
    };
}