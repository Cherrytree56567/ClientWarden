#pragma once
#include "query/query.h"

namespace clientwarden {
    class BitwardenQuery : public Query {
    public:
        BitwardenQuery(Vault& vault);
        ~BitwardenQuery() override;

        BitwardenQuery& filterByType(ItemType type) override;
        BitwardenQuery& filterByCreationDate(Timestamp start, Timestamp end) override;
        BitwardenQuery& filterByRevisionDate(Timestamp start, Timestamp end) override;
        BitwardenQuery& filterByDeletionDate(Timestamp start, Timestamp end) override;
        BitwardenQuery& filterByPasskey() override;
        BitwardenQuery& filterByBinned() override;
        BitwardenQuery& filterByUnbinned() override;
        BitwardenQuery& filterByArchived() override;
        BitwardenQuery& filterByUnarchived() override;
        BitwardenQuery& filterByFavorites() override;
        BitwardenQuery& filterByGroup(ItemId group_id) override;
        BitwardenQuery& filterNameByRegex(std::string regex) override;

        std::expected<std::vector<ItemId>, QueryError> get() override;
        std::expected<std::vector<std::pair<ItemType, ItemId>>, QueryError> getItems() override;

        Vendor getVendor() override;
    private:
        std::vector<ItemIds> item_ids;
    };
}