#pragma once
#include "vault/runtime/runtime.h"

namespace clientwarden::vendor::bitwarden::vault {
    class BitwardenRuntime : public Runtime {
    public:
        explicit BitwardenRuntime(Storage storage);
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

        RuntimeError markOfflineDeletedItem(ItemId uuid, bool mark) override;
        RuntimeError markOfflineDeletedFolder(ItemId uuid, bool mark) override;

        std::expected<bool, RuntimeError> isMarkedItem(ItemId uuid) override;
        std::expected<bool, RuntimeError> isMarkedFolder(ItemId uuid) override;

        std::expected<std::vector<ItemId>, RuntimeError> getMarkedItems() override;
        std::expected<std::vector<ItemId>, RuntimeError> getMarkedFolders() override;

        std::expected<Profile, RuntimeError> getProfile() override;
        std::expected<nlohmann::json, RuntimeError> getVaultInfo() override;
        
        std::expected<Botan::secure_vector<uint8_t>, RuntimeError> getVersion() override;
        RuntimeError storeVersion(Botan::secure_vector<uint8_t> version) override;

        Vendor getVendor() override;
    private:
        nlohmann::json m_vault_data_;
    };
}