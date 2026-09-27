#pragma once
#include <botan/secmem.h>
#include "clientwarden.h"

namespace clientwarden {
    /**
     * @brief Represents the result of an operation.
     */
    enum FolderError {
        Success,
        None
    };

    class Vault;

    class Folder {
    public:
        Folder(Vault& vault, ItemId id, bool item_creation);
        virtual ~Folder() = default;

        /**
         * @brief Sets the Folder's name.
         */
        virtual Folder& setName(const Botan::secure_vector<uint8_t>& name) = 0;
        /**
         * @brief Sets `o_name` with the Folder's name.
         */
        virtual Folder& getName(Botan::secure_vector<uint8_t>& o_name) = 0;

        /**
         * @brief Sets `o_name` with the Folder's Id.
         */
        virtual Folder& getId(ItemId& o_id) = 0;

        /**
         * @brief Pushes Folder Changes to remote and local.
         */
        virtual std::expected<ItemId, FolderError> commitItem() = 0;
        /**
         * @brief Deletes the Folder from remote and local.
         */
        virtual std::expected<void, FolderError> deleteItem() = 0;

        /**
         * @brief Returns the Vendor.
         */
        virtual Vendor getVendor() = 0;
    protected:
        ItemId m_id;
        bool m_is_created;
        bool m_init;
        Vault& m_vault;
    };
}