#pragma once
#include "folder/folder.h"

namespace clientwarden::vendor::bitwarden {
    struct BitwardenFolderObject {
        ItemId id;
        Botan::secure_vector<uint8_t> name;
        Timestamp revision_date;
    };

    class BitwardenFolder : public Folder {
    public:
        BitwardenFolder(Vault& vault, ItemId id, bool item_creation);
        ~BitwardenFolder() override;

        BitwardenFolder& setName(const Botan::secure_vector<uint8_t>& name) override;
        BitwardenFolder& getName(Botan::secure_vector<uint8_t>& o_name) override;

        BitwardenFolder& getId(ItemId& o_id) override;

        std::expected<ItemId, FolderError> commitItem() override;
        std::expected<void, FolderError> deleteItem() override;

        Vendor getVendor() override;
    private:
        BitwardenFolderObject m_object_;
    };
}