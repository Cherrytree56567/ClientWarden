#pragma once
#include "generic_item.h"

namespace clientwarden {
    /**
     * @brief Should be used by the Vendors Item Type (eg: BitwardenLoginItem).
     */
    template <typename GenericItemDerived, typename Derived>
    class GenericItemImpl : public GenericItemDerived {
    public:
        using GenericItemDerived::GenericItemDerived;

        /**
         * @brief These funcs override the GenericItemDerived funcs to return a Derived pointer
         *  to allow chained builder style calls.
         * 
         * See `generic_item.h` - `GenericItem` to view the individual func briefs.
         */
        Derived* setName(const Botan::secure_vector<uint8_t>& name) {
            this->setNameImpl(name);
            return static_cast<Derived*>(this);
        }

        Derived* setNotes(const Botan::secure_vector<uint8_t>& notes) {
            this->setNotesImpl(notes);
            return static_cast<Derived*>(this);
        }

        Derived* setGroups(const std::vector<ItemId>& group_ids) {
            this->setGroupsImpl(group_ids);
            return static_cast<Derived*>(this);
        }

        Derived* addGroup(const ItemId& group_id) {
            this->addGroupImpl(group_id);
            return static_cast<Derived*>(this);
        }

        Derived* removeGroup(const ItemId& group_id) {
            this->removeGroupImpl(group_id);
            return static_cast<Derived*>(this);
        }

        Derived* addField(const CustomField& field) {
            this->addFieldImpl(field);
            return static_cast<Derived*>(this);
        }

        Derived* removeField(const Botan::secure_vector<uint8_t>& field_name) {
            this->removeFieldImpl(field_name);
            return static_cast<Derived*>(this);
        }

        Derived* clearFields() {
            this->clearFieldsImpl();
            return static_cast<Derived*>(this);
        }

        Derived* getName(Botan::secure_vector<uint8_t>& o_name) {
            this->getNameImpl(o_name);
            return static_cast<Derived*>(this);
        }

        Derived* getNotes(Botan::secure_vector<uint8_t>& o_notes) {
            this->getNotesImpl(o_notes);
            return static_cast<Derived*>(this);
        }

        Derived* getGroups(std::vector<ItemId>& o_group_ids) {
            this->getGroupsImpl(o_group_ids);
            return static_cast<Derived*>(this);
        }

        Derived* getFields(std::vector<CustomField>& o_fields) {
            this->getFieldsImpl(o_fields);
            return static_cast<Derived*>(this);
        }

        Derived* getId(ItemId& o_id) {
            this->getIdImpl(o_id);
            return static_cast<Derived*>(this);
        }

        Derived* getCreation(std::string& o_time) {
            this->getCreationImpl(o_time);
            return static_cast<Derived*>(this);
        }

        Derived* getModification(std::string& o_time) {
            this->getModificationImpl(o_time);
            return static_cast<Derived*>(this);
        }

        Derived* getDeletion(std::string& o_time) {
            this->getDeletionImpl(o_time);
            return static_cast<Derived*>(this);
        }

        Derived* addAttachment(const Botan::secure_vector<uint8_t>& name, 
            const Botan::secure_vector<uint8_t>& content, ItemId& o_id,
            std::function<void(float)> on_progress = nullptr) {
            this->addAttachmentImpl(name, content, o_id, on_progress);
            return static_cast<Derived*>(this);
        }

        Derived* downloadAttachment(const ItemId& id, const std::filesystem::path& path,
            std::function<void(float)> on_progress = nullptr) {
            this->downloadAttachmentImpl(id, path, on_progress);
            return static_cast<Derived*>(this);
        }

        Derived* getAttachmentIds(std::vector<ItemId>& o_ids) {
            this->getAttachmentIdsImpl(o_ids);
            return static_cast<Derived*>(this);
        }

        Derived* getAttachmentName(const ItemId& id, Botan::secure_vector<uint8_t>& o_name) {
            this->getAttachmentNameImpl(id, o_name);
            return static_cast<Derived*>(this);
        }

        Derived* removeAttachment(const ItemId& id) {
            this->removeAttachmentImpl(id);
            return static_cast<Derived*>(this);
        }

        Derived* setFavorite(bool value) {
            this->setFavoriteImpl(value);
            return static_cast<Derived*>(this);
        }

        Derived* setReprompt(bool value) {
            this->setRepromptImpl(value);
            return static_cast<Derived*>(this);
        }

        Derived* getFavorite(bool& o_value) {
            this->getFavoriteImpl(o_value);
            return static_cast<Derived*>(this);
        }

        Derived* getReprompt(bool& o_value) {
            this->getRepromptImpl(o_value);
            return static_cast<Derived*>(this);
        }

        Derived* getType(ItemType& o_value) {
            this->getTypeImpl(o_value);
            return static_cast<Derived*>(this);
        }
    };
}