#include "generic_item.h"

namespace clientwarden {
    GenericItem::GenericItem(Vault& vault, ItemId id, bool item_creation) : m_id(id),
        m_is_created(item_creation), m_vault(vault) {
        m_init = true;
    }

    GenericItem::~GenericItem() {
        m_item_keys.clear();
    }

    GenericItem* GenericItem::setName(const Botan::secure_vector<uint8_t>& name) {
        setNameImpl(name);
        return this;
    }

    GenericItem* GenericItem::setNotes(const Botan::secure_vector<uint8_t>& notes) {
        setNotesImpl(notes);
        return this;
    }
    
    GenericItem* GenericItem::setGroups(const std::vector<ItemId>& group_ids) {
        setGroupsImpl(group_ids);
        return this;
    }
    
    GenericItem* GenericItem::addGroup(const ItemId& group_id) {
        addGroupImpl(group_id);
        return this;
    }
    
    GenericItem* GenericItem::removeGroup(const ItemId& group_id) {
        removeGroupImpl(group_id);
        return this;
    }
    
    GenericItem* GenericItem::addField(const CustomField& field) {
        addFieldImpl(field);
        return this;
    }
    
    GenericItem* GenericItem::removeField(const Botan::secure_vector<uint8_t>& field_name) {
        removeFieldImpl(field_name);
        return this;
    }
    
    GenericItem* GenericItem::clearFields() {
        clearFieldsImpl();
        return this;
    }

    GenericItem* GenericItem::getName(Botan::secure_vector<uint8_t>& o_name) {
        getNameImpl(o_name);
        return this;
    }
    
    GenericItem* GenericItem::getNotes(Botan::secure_vector<uint8_t>& o_notes) {
        getNotesImpl(o_notes);
        return this;
    }
    
    GenericItem* GenericItem::getGroups(std::vector<ItemId>& o_group_ids) {
        getGroupsImpl(o_group_ids);
        return this;
    }
    
    GenericItem* GenericItem::getFields(std::vector<CustomField>& o_fields) {
        getFieldsImpl(o_fields);
        return this;
    }
    
    GenericItem* GenericItem::getId(ItemId& o_id) {
        getIdImpl(o_id);
        return this;
    }
    
    GenericItem* GenericItem::getCreation(std::string& o_time) {
        getCreationImpl(o_time);
        return this;
    }
    
    GenericItem* GenericItem::getModification(std::string& o_time) {
        getModificationImpl(o_time);
        return this;
    }
    
    GenericItem* GenericItem::getDeletion(std::string& o_time) {
        getDeletionImpl(o_time);
        return this;
    }

    GenericItem* GenericItem::addAttachment(const Botan::secure_vector<uint8_t>& name, 
        const Botan::secure_vector<uint8_t>& content, ItemId& o_id,
        std::function<void(float)> on_progress) {
        addAttachmentImpl(name, content, o_id, on_progress);
        return this;
    }
    
    GenericItem* GenericItem::downloadAttachment(const ItemId& id, const std::filesystem::path& path,
        std::function<void(float)> on_progress) {
        downloadAttachmentImpl(id, path, on_progress);
        return this;
    }
    
    GenericItem* GenericItem::getAttachmentIds(std::vector<ItemId>& o_ids) {
        getAttachmentIdsImpl(o_ids);
        return this;
    }
    
    GenericItem* GenericItem::getAttachmentName(const ItemId& id, Botan::secure_vector<uint8_t>& o_name) {
        getAttachmentNameImpl(id, o_name);
        return this;
    }
    
    GenericItem* GenericItem::removeAttachment(const ItemId& id) {
        removeAttachmentImpl(id);
        return this;
    }

    GenericItem* GenericItem::setFavorite(bool value) {
        setFavoriteImpl(value);
        return this;
    }
    
    GenericItem* GenericItem::setReprompt(bool value) {
        setRepromptImpl(value);
        return this;
    }
    
    GenericItem* GenericItem::getFavorite(bool& o_value) {
        getFavoriteImpl(o_value);
        return this;
    }
    
    GenericItem* GenericItem::getReprompt(bool& o_value) {
        getRepromptImpl(o_value);
        return this;
    }
    
    GenericItem* GenericItem::getType(ItemType& o_value) {
        getTypeImpl(o_value);
        return this;
    }
}