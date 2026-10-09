#pragma once
#include <mutex>
#include <botan/secmem.h>
#include <nlohmann/json.hpp>
#include "clientwarden.h"
#include "../profiles/profile.h"

namespace clientwarden::vault {
    enum class RuntimeError {
        VaultNotFound,
        InvalidVault,
        ExistingItem,
        NotFound,
        Uninitialised,
        StorageFailure,
        Success
    };

    class Runtime {
    public:
        Runtime(std::shared_ptr<Storage> storage);
        virtual ~Runtime() = default;

        /**
         * @brief Load Vault is a separate func instead of inside the Runtime, bc if the Vault
         *  hasn't been logged into yet, it cannot search for a non-existent vault JSON.
         */
        virtual RuntimeError loadVault() = 0;

        /**
         * @brief Returns m_vault_data.
         */
        virtual std::expected<nlohmann::json, RuntimeError> getVaultData() = 0;
        /**
         * @brief Returns a nlohmann::json array that contains all items as raw JSON.
         */
        virtual std::expected<nlohmann::json, RuntimeError> getItems() = 0;

        /**
         * @brief Returns the ItemId's of all the items in the Vault.
         */
        virtual std::expected<std::vector<ItemId>, RuntimeError> getItemIds() = 0;
        /**
         * @brief Returns a single item with a matching uuid as raw JSON.
         */
        virtual std::expected<nlohmann::json, RuntimeError> getItem(ItemId uuid) = 0;
        /**
         * @brief Replaces an existing item with a matching uuid with the new provided item.
         */
        virtual RuntimeError updateItem(ItemId uuid, nlohmann::json item) = 0;
        /**
         * @brief Adds an item to local Vault.
         */
        virtual RuntimeError addItem(nlohmann::json item) = 0;
        /**
         * @brief Removes an item from the local vault with a matching ItemId.
         */
        virtual RuntimeError removeItem(ItemId uuid) = 0;

        /**
         * @brief Returns a list of all folder ItemIds.
         */
        virtual std::expected<std::vector<ItemId>, RuntimeError> getFolders() = 0;
        /**
         * @brief Returns a folder with a matching ItemId as raw JSON.
         */
        virtual std::expected<nlohmann::json, RuntimeError> getFolder(ItemId uuid) = 0;
        /**
         * @brief Replaces an existing folder with a matching ItemId with the new provided folder.
         */
        virtual RuntimeError updateFolder(ItemId uuid, nlohmann::json folder) = 0;
        /**
         * @brief Adds a folder to the local Vault.
         */
        virtual RuntimeError addFolder(nlohmann::json folder) = 0;
        /**
         * @brief Removes a folder with a matching ItemId from the local Vault.
         */
        virtual RuntimeError removeFolder(ItemId uuid) = 0;

        /**
         * @brief Flags or Unflags an Item as deleted while offline.
         */
        virtual RuntimeError markOfflineDeletedItem(ItemId uuid, bool mark) = 0;
        /**
         * @brief Flags or Unflags an item as created while offline
         */
        virtual RuntimeError markOfflineCreatedItem(ItemId uuid, bool mark) = 0;
        /**
         * @brief Flags or Unflags a Folder as deleted while offline.
         */
        virtual RuntimeError markOfflineDeletedFolder(ItemId uuid, bool mark) = 0;

        /**
         * @brief Returns the flag of an Item with a matching ItemId.
         */
        virtual std::expected<bool, RuntimeError> isMarkedItem(ItemId uuid) = 0;
        /**
         * @brief Returns the flag of a Folder with a matching ItemId.
         */
        virtual std::expected<bool, RuntimeError> isMarkedFolder(ItemId uuid) = 0;

        /**
         * @brief Returns an array of Items which are marked as Deleted Offline.
         */
        virtual std::expected<std::vector<ItemId>, RuntimeError> getMarkedItems() = 0;
        /**
         * @brief Returns an array of Folders which are marked as Deleted Offline.
         */
        virtual std::expected<std::vector<ItemId>, RuntimeError> getMarkedFolders() = 0;

        /**
         * @brief Returns the profile contained in the local Vault.
         */
        virtual std::expected<Profile, RuntimeError> getProfile() = 0;
        /**
         * @brief Returns important info about the local Vault, such as Decryption Parameters, etc.
         */
        virtual std::expected<nlohmann::json, RuntimeError> getVaultInfo() = 0;
        
        /**
         * @brief Gets the Current versiun of the local Vault.
         */
        virtual std::expected<Botan::secure_vector<uint8_t>, RuntimeError> getVersion() = 0;
        /**
         * @brief Stores a version in the local Vault.
         */
        virtual RuntimeError storeVersion(Botan::secure_vector<uint8_t> version) = 0;

        /**
         * @brief Returns the Vendor.
         */
        virtual Vendor getVendor() = 0;
    protected:
        std::recursive_mutex m_mutex;
        nlohmann::json m_vault_data;
        std::shared_ptr<Storage> m_storage;
    };
}