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

    enum class EntityType {
        Item,
        Folder,
        Attachment,
        Unknown
    };

    enum class ChangeType {
        Created,
        CreatedPartial,
        Updated,
        Deleted,
        Unknown
    };

    constexpr std::string_view getString(EntityType type) {
        switch (type) {
            case EntityType::Item:
                return "item";
            case EntityType::Folder:
                return "folder";
            case EntityType::Attachment:
                return "attachment";
            default:
                return "unknown";
        }
    }

    constexpr EntityType getEntityType(std::string_view type) {
        if (type == "item") {
            return EntityType::Item;
        } else if (type == "folder") {
            return EntityType::Folder;
        } else if (type == "attachment") {
            return EntityType::Attachment;
        } else {
            return EntityType::Unknown;
        }
    }

    constexpr std::string_view getString(ChangeType type) {
        if (type == ChangeType::Created) {
            return "created";
        } else if (type == ChangeType::CreatedPartial) {
            return "createdPartial";
        } else if (type == ChangeType::Updated) {
            return "updated";
        } else if (type == ChangeType::Deleted) {
            return "deleted";
        } else {
            return "unknown";
        }
    }

    constexpr ChangeType getChangeType(std::string_view type) {
        switch (type) {
            case "created":
                return ChangeType::Created;
            case "createdPartial":
                return ChangeType::CreatedPartial;
            case "updated":
                return ChangeType::Updated;
            case "deleted":
                return ChangeType::Deleted;
            default:
                return ChangeType::Unknown;
        }
    }

    struct Entity {
        EntityType type = EntityType::Unknown;
        ItemId id;
        ItemId parent_id = "";
    };

    struct PendingChange {
        Entity entity;
        ChangeType type = ChangeType::Unknown;
        nlohmann::json base;
        std::string revisionDate;
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
         * @brief Add attachment json to the matching ItemId from the local Vault.
         */
        virtual RuntimeError addAttachment(ItemId uuid, nlohmann::json attachment) = 0;
        /**
         * @brief Update attachment json to the matching ItemId from the local Vault.
         */
        virtual RuntimeError updateAttachment(ItemId uuid, ItemId attachment_id, nlohmann::json attachment) = 0;
        /**
         * @brief Remove attachment json to the matching ItemId from the local Vault.
         */
        virtual RuntimeError removeAttachment(ItemId uuid, ItemId attachment_id) = 0;
        /**
         * @brief Returns the attachment with a matching ItemId as raw JSON.
         */
        virtual std::expected<nlohmann::json, RuntimeError> getAttachment(ItemId uuid, ItemId attachment_id) = 0;

        /**
         * @brief Records an offline action. Requires a body and last modified date if it is an
         *  Updated change.
         */
        virtual RuntimeError record(PendingChange change) = 0;
        /**
         * @brief Removes a record with the matching entity.
         */
        virtual RuntimeError removeRecord(Entity entity) = 0;
        /**
         * @brief Returns an offline action that matches the entity provided.
         */
        virtual std::expected<PendingChange, RuntimeError> getRecord(Entity entity) = 0;
        /**
         * @brief Returns a bool if the record with the matching entity exists.
         */
        virtual std::expected<bool, RuntimeError> recordExists(Entity entity) = 0;

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