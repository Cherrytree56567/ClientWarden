#pragma once
#include <string>
#include "clientwarden.h"

namespace clientwarden {
    /**
     * @brief Represents the result of an operation.
     */
    enum QueryError {
        Success,
        None
    };

    class Vault;

    class Query {
    public:
        Query(Vault& vault);
        virtual ~Query() = default;

        /**
         * @brief Filters by Type.
         */
        virtual Query& filterByType(ItemType type) = 0;
        /**
         * @brief Filters by Creation Date using the provided start and end.
         */
        virtual Query& filterByCreationDate(std::time_t start, std::time_t end) = 0;
        /**
         * @brief Filters by Revision Date using the provided start and end.
         */
        virtual Query& filterByRevisionDate(std::time_t start, std::time_t end) = 0;
        /**
         * @brief Filters by Deletion Date using the provided start and end.
         */
        virtual Query& filterByDeletionDate(std::time_t start, std::time_t end) = 0;
        /**
         * @brief Filters by Items which have a passkey.
         */
        virtual Query& filterByPasskey() = 0;
        /**
         * @brief Filters by Binned Items.
         */
        virtual Query& filterByBinned() = 0;
        /**
         * @brief Filters by Unbinned Items.
         */
        virtual Query& filterByUnbinned() = 0;
        /**
         * @brief Filters by Archived Items.
         */
        virtual Query& filterByArchived() = 0;
        /**
         * @brief Filters by Unarchived Items.
         */
        virtual Query& filterByUnarchived() = 0;
        /**
         * @brief Filters by Favorited Items.
         */
        virtual Query& filterByFavorites() = 0;
        /**
         * @brief Filters by Items in the provided group.
         */
        virtual Query& filterByGroup(ItemId group_id) = 0;
        /**
         * @brief Filters by Items with the provided name.
         */
        virtual Query& filterNameByRegex(std::string regex) = 0;

        /**
         * @brief Returns a list of the filtered Items.
         */
        virtual std::expected<std::vector<ItemId>, QueryError> get() = 0;
        /**
         * @brief Returns a list of the filtered Items with their respective Item Types.
         */
        virtual std::expected<std::vector<std::pair<ItemType, ItemId>>, QueryError> getItems() = 0;

        /**
         * @brief Returns the Vendor.
         */
        virtual Vendor getVendor() = 0;
    protected:
        bool m_init;
        Vault& m_vault;
    };
}