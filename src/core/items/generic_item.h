#pragma once
#include <botan/secmem.h>
#include "clientwarden.h"

namespace clientwarden {
    /**
     * @brief The Custom Field Types in Bitwarden (can be expanded).
     */
    enum class CustomFieldType {
        Text,
        Hidden,
        Checkbox,
        Linked
    };
    
    /**
     * @brief Represents a Custom Field.
     * @param field The Field Type.
     * @param name The Field Name.
     * @param value The Field Value.
     */
    struct CustomField {
        CustomFieldType field;
        Botan::secure_vector<uint8_t> name;
        Botan::secure_vector<uint8_t> value;
    };

    /**
     * @brief Represents the result of an operation.
     */
    enum ItemError {
        Success,
        None
    };

    class Vault;

    class GenericItem {
    public:
        GenericItem(Vault& vault, ItemId id, bool item_creation);
        virtual ~GenericItem();

        /**
         * @brief Sets the Item Name
         */
        GenericItem* setName(const Botan::secure_vector<uint8_t>& name);
        /**
         * @brief Sets the Item Note
         */
        GenericItem* setNotes(const Botan::secure_vector<uint8_t>& notes);
        /**
         * @brief Sets the Groups the Item is in.
         * 
         * On Bitwarden, this is limited to one group id and groups are called folders.
         */
        GenericItem* setGroups(const std::vector<ItemId>& group_ids);
        /**
         * @brief Adds the Item to a group (folder on BitWarden).
         */
        GenericItem* addGroup(const ItemId& group_id);
        /**
         * @brief Removes the Item from a group (folder on BitWarden).
         */
        GenericItem* removeGroup(const ItemId& group_id);
        /**
         * @brief Adds a field to the Item.
         */
        GenericItem* addField(const CustomField& field);
        /**
         * @brief Removes a field from the Item.
         */
        GenericItem* removeField(const Botan::secure_vector<uint8_t>& field_name);
        /**
         * @brief Removes all fields from the Item.
         */
        GenericItem* clearFields();

        /**
         * @brief Sets `o_name` with the Item's name.
         */
        GenericItem* getName(Botan::secure_vector<uint8_t>& o_name);
        /**
         * @brief Sets `o_notes` with the Item's name.
         */
        GenericItem* getNotes(Botan::secure_vector<uint8_t>& o_notes);
        /**
         * @brief Sets `o_group_ids` with a list of the Groups the Item is in.
         */
        GenericItem* getGroups(std::vector<ItemId>& o_group_ids);
        /**
         * @brief Sets `o_fields` with the Item's fields.
         */
        GenericItem* getFields(std::vector<CustomField>& o_fields);
        /**
         * @brief Sets `o_id` with the Item's id.
         */
        GenericItem* getId(ItemId& o_id);
        /**
         * @brief Sets `o_time` with the Item's creation date.
         */
        GenericItem* getCreation(std::string& o_time);
        /**
         * @brief Sets `o_time` with the Item's modification date.
         */
        GenericItem* getModification(std::string& o_time);
        /**
         * @brief Sets `o_time` with the Item's deletion date.
         */
        GenericItem* getDeletion(std::string& o_time);

        /**
         * @brief Uploads an attachment with the following name and content to the server and sets
         *  `o_id` with the attachment's id and executes `on_progress` when upload progresses.
         */
        GenericItem* addAttachment(const Botan::secure_vector<uint8_t>& name, 
            const Botan::secure_vector<uint8_t>& content, ItemId& o_id,
            std::function<void(float)> on_progress = nullptr);
        /**
         * @brief Downloads the attachment using the provided Attachment ID to the provided path,
         *  and updates progress using on_progresss.
         */
        GenericItem* downloadAttachment(const ItemId& id, const std::filesystem::path& path,
            std::function<void(float)> on_progress = nullptr);
        /**
         * @brief Sets `o_ids` with a list of all Attachments in the Item.
         */
        GenericItem* getAttachmentIds(std::vector<ItemId>& o_ids);
        /**
         * @brief Sets `o_name` with the Attachment's name from the provided id.
         */
        GenericItem* getAttachmentName(const ItemId& id, Botan::secure_vector<uint8_t>& o_name);
        /**
         * @brief Removes the attachment using the provided id.
         */
        GenericItem* removeAttachment(const ItemId& id);

        /**
         * @brief Sets the Item as a favorite.
         */
        GenericItem* setFavorite(bool value);
        /**
         * @brief Sets the Item to reprompt for the master password.
         */
        GenericItem* setReprompt(bool value);
        /**
         * @brief Sets `o_value` with the Item's favorite value.
         */
        GenericItem* getFavorite(bool& o_value);
        /**
         * @brief Sets `o_value` with the Item's reprompt value.
         */
        GenericItem* getReprompt(bool& o_value);
        /**
         * @brief Sets `o_value` with the Item's type.
         */
        GenericItem* getType(ItemType& o_value);

        /**
         * @brief Creates or pushes the item to the Remote and Local.
         */
        virtual std::expected<void, ItemError> commitItem() = 0;
        /**
         * @brief Removes the item from Remote and Local.
         */
        virtual std::expected<void, ItemError> deleteItem() = 0;
        /**
         * @brief Bins the item to the Remote and Local.
         */
        virtual std::expected<void, ItemError> binItem() = 0;
        /**
         * @brief Un-Bins the item to the Remote and Local.
         */
        virtual std::expected<void, ItemError> unBinItem() = 0;
        /**
         * @brief Archives the item to the Remote and Local.
         */
        virtual std::expected<void, ItemError> archiveItem() = 0;
        /**
         * @brief Un-Archives the item to the Remote and Local.
         */
        virtual std::expected<void, ItemError> unArchiveItem() = 0;

        /**
         * @brief Returns the Vendor.
         */
        virtual Vendor getVendor() = 0;
    protected:
        /**
         * @brief Implementations of all the above funcs.
         */
        virtual void setNameImpl(const Botan::secure_vector<uint8_t>& name) = 0;
        virtual void setNotesImpl(const Botan::secure_vector<uint8_t>& name) = 0;
        virtual void setGroupsImpl(const std::vector<ItemId>& group_ids) = 0;
        virtual void addGroupImpl(const ItemId& group_id) = 0;
        virtual void removeGroupImpl(const ItemId& group_id) = 0;
        virtual void addFieldImpl(const CustomField& field) = 0;
        virtual void removeFieldImpl(const Botan::secure_vector<uint8_t>& name) = 0;
        virtual void clearFieldsImpl() = 0;

        virtual void getNameImpl(Botan::secure_vector<uint8_t>& o_name) = 0;
        virtual void getNotesImpl(Botan::secure_vector<uint8_t>& o_name) = 0;
        virtual void getGroupsImpl(std::vector<ItemId>& o_group_ids) = 0;
        virtual void getFieldsImpl(std::vector<CustomField>& o_fields) = 0;
        virtual void getIdImpl(ItemId& o_id) = 0;
        virtual void getCreationImpl(std::string& o_time) = 0;
        virtual void getModificationImpl(std::string& o_time) = 0;
        virtual void getDeletionImpl(std::string& o_time) = 0;

        virtual void addAttachmentImpl(const Botan::secure_vector<uint8_t>& name, 
            const Botan::secure_vector<uint8_t>& content, ItemId& o_id,
            std::function<void(float)> on_progress = nullptr) = 0;
        virtual void downloadAttachmentImpl(const ItemId& id, const std::filesystem::path& path,
            std::function<void(float)> on_progress = nullptr) = 0;
        virtual void getAttachmentIdsImpl(std::vector<ItemId>& o_ids) = 0;
        virtual void getAttachmentNameImpl(const ItemId& id, Botan::secure_vector<uint8_t>& o_name) = 0;
        virtual void removeAttachmentImpl(const ItemId& id) = 0;

        virtual void setFavoriteImpl(bool value) = 0;
        virtual void setRepromptImpl(bool value) = 0;
        virtual void getFavoriteImpl(bool& o_value) = 0;
        virtual void getRepromptImpl(bool& o_value) = 0;
        virtual void getTypeImpl(ItemType& o_value) = 0;

        /**
         * @brief Sensitive Data that should be cleared on destruction
         */
        ItemKey m_item_keys;

        ItemId m_id;
        bool m_is_created;
        bool m_init;
        Vault& m_vault;
    };
}