#pragma once
#include "items/generic_item.h"

namespace clientwarden::vendor::bitwarden {
    class BitwardenGenericItem {
    public:
        BitwardenGenericItem(Vault& vault, ItemId id, bool item_creation);
        ~BitwardenGenericItem() override;

        std::expected<ItemId, ItemError> commitItem() override;
        std::expected<void, ItemError> deleteItem() override;
        std::expected<void, ItemError> binItem() override;
        std::expected<void, ItemError> unBinItem() override;
        std::expected<void, ItemError> archiveItem() override;
        std::expected<void, ItemError> unArchiveItem() override;

        Vendor getVendor() override;
    protected:
        void setNameImpl(const Botan::secure_vector<uint8_t>& name) override;
        void setNotesImpl(const Botan::secure_vector<uint8_t>& name) override;
        void setGroupsImpl(const std::vector<ItemId>& group_ids) override;
        void addGroupImpl(const ItemId& group_id) override;
        void removeGroupImpl(const ItemId& group_id) override;
        void addFieldImpl(const CustomField& field) override;
        void removeFieldImpl(const Botan::secure_vector<uint8_t>& name) override;
        void clearFieldsImpl() override;

        void getNameImpl(Botan::secure_vector<uint8_t>& o_name) override;
        void getNotesImpl(Botan::secure_vector<uint8_t>& o_name) override;
        void getGroupsImpl(std::vector<ItemId>& o_group_ids) override;
        void getFieldsImpl(std::vector<CustomField>& o_fields) override;
        void getIdImpl(ItemId& o_id) override;
        void getCreationImpl(std::string& o_time) override;
        void getModificationImpl(std::string& o_time) override;
        void getDeletionImpl(std::string& o_time) override;

        void addAttachmentImpl(const Botan::secure_vector<uint8_t>& name, 
            const Botan::secure_vector<uint8_t>& content, ItemId& o_id,
            std::function<void(float)> on_progress = nullptr) override;
        void downloadAttachmentImpl(const ItemId& id, const std::filesystem::path& path,
            std::function<void(float)> on_progress = nullptr) override;
        void getAttachmentIdsImpl(std::vector<ItemId>& o_ids) override;
        void getAttachmentNameImpl(const ItemId& id, Botan::secure_vector<uint8_t>& o_name) override;
        void removeAttachmentImpl(const ItemId& id) override;

        void setFavoriteImpl(bool value) override;
        void setRepromptImpl(bool value) override;
        void getFavoriteImpl(bool& o_value) override;
        void getRepromptImpl(bool& o_value) override;
        void getTypeImpl(ItemType& o_value) override;
    protected:
        nlohmann::json m_data_;
        nlohmann::json m_field_data_;
        bool m_enable_data_field_ = true;
        bool m_enable_bank_account_field_ = false;
        bool m_enable_passport_field_ = false;
        bool m_enable_drivers_license_field_ = false;
    };
}