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
         * hasn't been logged into yet, it cannot search for a non-existent vault JSON.
         */
        virtual void loadVault() = 0;

        virtual nlohmann::json getVaultData() = 0;
        virtual nlohmann::json getItems() = 0;

        virtual Botan::secure_vector<ItemId> getItemIds() = 0;
        virtual nlohmann::json getItem(ItemId uuid) = 0;
        virtual void updateItem(ItemId uuid, nlohmann::json item) = 0;
        virtual void addItem(nlohmann::json item) = 0;
        virtual void removeItem(ItemId uuid) = 0;

        virtual Botan::secure_vector<ItemId> getFolders() = 0;
        virtual nlohmann::json getFolder(ItemId uuid) = 0;
        virtual void updateFolder(ItemId uuid, nlohmann::json item) = 0;
        virtual void addFolder(nlohmann::json item) = 0;
        virtual void removeFolder(ItemId uuid) = 0;

        virtual void markOfflineDeletedItem(ItemId uuid, bool mark) = 0;
        virtual void markOfflineDeletedFolder(ItemId uuid, bool mark) = 0;

        virtual bool isMarkedItem(ItemId uuid) = 0;
        virtual bool isMarkedFolder(ItemId uuid) = 0;

        virtual Botan::secure_vector<ItemId> getMarkedItems() = 0;
        virtual Botan::secure_vector<ItemId> getMarkedFolders() = 0;

        virtual Profile getProfile() = 0;
        virtual nlohmann::json getVaultInfo() = 0;
        
        virtual Botan::secure_vector<uint8_t> getVersion() = 0;
        virtual void storeVersion(Botan::secure_vector<uint8_t> version) = 0;

        virtual Vendor getVendor() = 0;
    protected:
        std::recursive_mutex m_mutex;
        nlohmann::json m_vault_data;
    };
}