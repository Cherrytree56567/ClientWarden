#pragma once
#include <mutex>
#include <botan/secmem.h>
#include <nlohmann/json.hpp>
#include "clientwarden.h"
#include "../profiles/profile.h"

namespace clientwarden::vault {
    class Runtime {
    public:
        Runtime();
        virtual ~Runtime() = default;

        /**
         * @brief Load Vault is a separate func instead of inside the Runtime, bc if the Vault
         *  hasn't been logged into yet, it cannot search for a non-existent vault JSON.
         */
        virtual void loadVault() = 0;

        /**
         * @brief Returns m_vault_data.
         */
        virtual nlohmann::json getVaultData() = 0;
        /**
         * @brief Returns a nlohmann::json array that contains all items as raw JSON.
         */
        virtual nlohmann::json getItems() = 0;

        /**
         * @brief Returns the ItemId's of all the items in the Vault.
         */
        virtual Botan::secure_vector<ItemId> getItemIds() = 0;
        /**
         * @brief Returns a single item with a matching uuid as raw JSON.
         */
        virtual nlohmann::json getItem(ItemId uuid) = 0;
        /**
         * @brief Replaces an existing item with a matching uuid with the new provided item.
         */
        virtual void updateItem(ItemId uuid, nlohmann::json item) = 0;
        /**
         * @brief Adds an item to local Vault.
         */
        virtual void addItem(nlohmann::json item) = 0;
        /**
         * @brief Removes an item from the local vault with a matching ItemId.
         */
        virtual void removeItem(ItemId uuid) = 0;

        /**
         * @brief Returns a list of all folder ItemIds.
         */
        virtual Botan::secure_vector<ItemId> getFolders() = 0;
        /**
         * @brief Returns a folder with a matching ItemId as raw JSON.
         */
        virtual nlohmann::json getFolder(ItemId uuid) = 0;
        /**
         * @brief Replaces an existing folder with a matching ItemId with the new provided folder.
         */
        virtual void updateFolder(ItemId uuid, nlohmann::json folder) = 0;
        /**
         * @brief Adds a folder to the local Vault.
         */
        virtual void addFolder(nlohmann::json folder) = 0;
        /**
         * @brief Removes a folder with a matching ItemId from the local Vault.
         */
        virtual void removeFolder(ItemId uuid) = 0;

        /**
         * @brief Flags or Unflags an Item as deleted while offline.
         */
        virtual void markOfflineDeletedItem(ItemId uuid, bool mark) = 0;
        /**
         * @brief Flags or Unflags a Folder as deleted while offline.
         */
        virtual void markOfflineDeletedFolder(ItemId uuid, bool mark) = 0;

        /**
         * @brief Returns the flag of an Item with a matching ItemId.
         */
        virtual bool isMarkedItem(ItemId uuid) = 0;
        /**
         * @brief Returns the flag of a Folder with a matching ItemId.
         */
        virtual bool isMarkedFolder(ItemId uuid) = 0;

        /**
         * @brief Returns an array of Items which are marked as Deleted Offline.
         */
        virtual Botan::secure_vector<ItemId> getMarkedItems() = 0;
        /**
         * @brief Returns an array of Folders which are marked as Deleted Offline.
         */
        virtual Botan::secure_vector<ItemId> getMarkedFolders() = 0;

        /**
         * @brief Returns the profile contained in the local Vault.
         */
        virtual Profile getProfile() = 0;
        /**
         * @brief Returns important info about the local Vault, such as Decryption Parameters, etc.
         */
        virtual nlohmann::json getVaultInfo() = 0;
        
        /**
         * @brief Gets the Current versiun of the local Vault.
         */
        virtual Botan::secure_vector<uint8_t> getVersion() = 0;
        /**
         * @brief Stores a version in the local Vault.
         */
        virtual void storeVersion(Botan::secure_vector<uint8_t> version) = 0;

        /**
         * @brief Returns the Vendor.
         */
        virtual Vendor getVendor() = 0;
    protected:
        std::recursive_mutex m_mutex;
        nlohmann::json m_vault_data;
    };
}