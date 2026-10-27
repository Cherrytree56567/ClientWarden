#include "bitwarden_generic_item.h"

namespace clientwarden::vendor::bitwarden {
    BitwardenGenericItem::BitwardenGenericItem(Vault& vault, ItemId id, bool item_creation) :
        GenericItem(vault, id, item_creation) {
        if (item_creation) {
            return;
        }

        m_id = id;

        std::expected<nlohmann::json, RuntimeError> item_err = 
            m_vault.getOrchestrator()->getRuntime()->getItem(id);
        
        if (!item_err.has_value()) {
            return;
        }

        m_data_ = item_err.value();

        std::expected<bool, VersioningError> data_err = 
            m_vault.getVersioning()->hasFeature(std::to_underlying(BitwardenFeature::DataField));
        
        if (!data_err.has_value()) {
            m_enable_data_field_ = true;
        } else {
            m_enable_data_field_ = data_err.value();
        }

        if (m_data_.contains("data") && m_enable_data_field_) {
            if (m_data_["data"].is_string()) {
                if (nlohmann::json::accept(m_data_["data"].get<std::string>())) {
                    m_field_data_ = nlohmann::json::parse(m_data_["data"].get<std::string>());
                }
            } else {
                m_field_data_ = m_data_["data"];

                if (m_field_data_.contains("fields")) {
                    m_field_data_["Fields"] = m_field_data_["fields"];
                    m_field_data_.erase("fields");

                    for (nlohmann::json& field : m_field_data_["Fields"]) {
                        if (field.contains("name")) {
                            field["Name"] = field["name"];
                            field.erase("name");
                        }

                        if (field.contains("type")) {
                            field["Type"] = field["type"];
                            field.erase("type");
                        }

                        if (field.contains("value")) {
                            field["Value"] = field["value"];
                            field.erase("value");
                        }
                    }
                }
            }
        }

        std::expected<ItemKey, CryptoErrors> item_key_err;

        if (m_data_.contains("key") && m_data_["key"].is_string()) {
            item_key_err = m_vault.getOrchestrator()->getCrypto()->resolveItemKey(m_data_["key"]);
        } else {
            item_key_err = m_vault.getOrchestrator()->getCrypto()->getItemKeys();
        }

        if (!item_key_err.has_value()) {
            return;
        }

        m_item_keys = std::move(item_key_err.value());

        m_init = true;
    }

    BitwardenGenericItem::~BitwardenGenericItem() {
        m_item_keys.clear();
        m_init = false;
    }
    
    std::expected<void, ItemError> BitwardenGenericItem::commitItem() {
        if (!m_init) {
            return std::unexpected(ItemError::Uninitialised);
        }

        m_item_keys.clear();
        m_init = false;

        if (m_enable_data_field_ && !m_field_data_.is_null()) {
            m_data_["data"] = m_field_data_.dump();
        }

        OrchestratorError action_err = 
            m_vault.getOrchestrator()->updateItem(m_data_);
        
        if (!action_err.has_value()) {
            return std::unexpected(ItemError::OrchestratorError);
        }

        return {};
    }
    
    std::expected<void, ItemError> BitwardenGenericItem::deleteItem() {
        if (!m_init) {
            return std::unexpected(ItemError::Uninitialised);
        }
        
        m_item_keys.clear();
        m_init = false;

        OrchestratorError action_err = 
            m_vault.getOrchestrator()->deleteItem(m_id);
        
        if (!action_err.has_value()) {
            return std::unexpected(ItemError::OrchestratorError);
        }

        return {};
    }
    
    std::expected<void, ItemError> BitwardenGenericItem::binItem() {
        if (!m_init) {
            return std::unexpected(ItemError::Uninitialised);
        }
        
        m_item_keys.clear();
        m_init = false;

        if (m_enable_data_field_ && !m_field_data_.is_null()) {
            m_data_["data"] = m_field_data_.dump();
        }

        /**
         * @note We must update the item as well, bc even though we are binning it, it doesnt mean
         *  that the item shouldnt be updated.
         */
        OrchestratorError action_err = 
            m_vault.getOrchestrator()->updateItem(m_data_);

        OrchestratorError action_extra_err = 
            m_vault.getOrchestrator()->softDeleteItem(m_id);
        
        if (!action_err.has_value() || !action_extra_err.has_value()) {
            return std::unexpected(ItemError::OrchestratorError);
        }

        return {};
    }
    
    std::expected<void, ItemError> BitwardenGenericItem::unBinItem() {
        if (!m_init) {
            return std::unexpected(ItemError::Uninitialised);
        }
        
        m_item_keys.clear();
        m_init = false;

        if (m_enable_data_field_ && !m_field_data_.is_null()) {
            m_data_["data"] = m_field_data_.dump();
        }

        OrchestratorError action_err = 
            m_vault.getOrchestrator()->updateItem(m_data_);

        OrchestratorError action_extra_err = 
            m_vault.getOrchestrator()->restoreItem(m_id);
        
        if (!action_err.has_value() || !action_extra_err.has_value()) {
            return std::unexpected(ItemError::OrchestratorError);
        }

        return {};
    }
    
    std::expected<void, ItemError> BitwardenGenericItem::archiveItem() {
        if (!m_init) {
            return std::unexpected(ItemError::Uninitialised);
        }
        
        m_item_keys.clear();
        m_init = false;

        if (m_enable_data_field_ && !m_field_data_.is_null()) {
            m_data_["data"] = m_field_data_.dump();
        }

        OrchestratorError action_err = 
            m_vault.getOrchestrator()->updateItem(m_data_);

        OrchestratorError action_extra_err = 
            m_vault.getOrchestrator()->archiveItem(m_id);
        
        if (!action_err.has_value() || !action_extra_err.has_value()) {
            return std::unexpected(ItemError::OrchestratorError);
        }

        return {};
    }
    
    std::expected<void, ItemError> BitwardenGenericItem::unArchiveItem() {
        if (!m_init) {
            return std::unexpected(ItemError::Uninitialised);
        }
        
        m_item_keys.clear();
        m_init = false;

        if (m_enable_data_field_ && !m_field_data_.is_null()) {
            m_data_["data"] = m_field_data_.dump();
        }

        OrchestratorError action_err = 
            m_vault.getOrchestrator()->updateItem(m_data_);

        OrchestratorError action_extra_err = 
            m_vault.getOrchestrator()->unArchiveItem(m_id);
        
        if (!action_err.has_value() || !action_extra_err.has_value()) {
            return std::unexpected(ItemError::OrchestratorError);
        }

        return {};
    }
    
    Vendor BitwardenGenericItem::getVendor() {
        return Vendor::BitWarden;
    }
    
    void BitwardenGenericItem::setNameImpl(const Botan::secure_vector<uint8_t>& name) {
        if (!m_init) {
            return;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->encrypt(name, m_item_keys);
        
        if (!value_err.has_value()) {
            return;
        }

        std::string value = utils::getString(value_err.value());

        if (m_enable_data_field_) {
            m_field_data_["Name"] = value;
        }

        m_data_["name"] = std::move(value);
    }
    
    void BitwardenGenericItem::setNotesImpl(const Botan::secure_vector<uint8_t>& notes) {
        if (!m_init) {
            return;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->encrypt(notes, m_item_keys);
        
        if (!value_err.has_value()) {
            return;
        }

        std::string value = utils::getString(value_err.value());

        if (m_enable_data_field_) {
            m_field_data_["Notes"] = value;
        }
        
        m_data_["notes"] = std::move(value);
    }
    
    void BitwardenGenericItem::setGroupsImpl(const std::vector<ItemId>& group_ids) {
        if (!m_init) {
            return;
        }

        if (group_ids.empty()) {
            return;
        }

        if (group_ids[0] == "" || group_ids[0] == "00000000-0000-0000-0000-000000000000") {
            m_data_["folderId"] = nullptr;
        } else {
            m_data_["folderId"] = group_ids[0];
        }
    }
    
    void BitwardenGenericItem::addGroupImpl(const ItemId& group_id) {
        if (!m_init) {
            return;
        }

        if (group_id == "" || group_id == "00000000-0000-0000-0000-000000000000") {
            m_data_["folderId"] = nullptr;
        } else {
            m_data_["folderId"] = group_id;
        }
    }
    
    void BitwardenGenericItem::removeGroupImpl(const ItemId& group_id) {
        if (!m_init) {
            return;
        }

        m_data_["folderId"] = nullptr;
    }
    
    void BitwardenGenericItem::addFieldImpl(const CustomField& field) {
        if (!m_init) {
            return;
        }

        if (!m_data_.contains("fields") || !m_data_["fields"].is_array()) {
            m_data_["fields"] = nlohmann::json::array();
        }

        if (m_enable_data_field_ && (!m_field_data_.contains("Fields") || 
            !m_field_data_["Fields"].is_array())) {
            m_field_data_["fields"] = nlohmann::json::array();
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> name_err = 
            m_vault.getOrchestrator()->getCrypto()->encrypt(field.name, m_item_keys);

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->encrypt(field.value, m_item_keys);
        
        if (!name_err.has_value() || !value_err.has_value()) {
            return;
        }

        std::string name = utils::getString(name_err.value());
        std::string value = utils::getString(value_err.value());

        nlohmann::json field_data;
        nlohmann::json data_field_data;

        switch (field.type) {
            case CustomFieldType::Text:
            case CustomFieldType::Hidden:
            case CustomFieldType::Checkbox:
                data_field_data["Name"] = name;
                data_field_data["Value"] = value;
                data_field_data["Type"] = std::to_underlying(field.type);

                field_data["linkedId"] = nullptr;
                field_data["name"] = std::move(name);
                field_data["value"] = std::move(value);
                field_data["type"] = std::to_underlying(field.type);
                break;
            case CustomFieldType::Linked:
                data_field_data["Name"] = name;
                data_field_data["LinkedId"] = std::stoi(field.value);
                data_field_data["Type"] = std::to_underlying(field.type);
                
                field_data["linkedId"] = std::stoi(field.value);
                field_data["name"] = std::move(name);
                field_data["value"] = nullptr;
                field_data["type"] = std::to_underlying(field.type);
                break;
            default:
                return;
        }

        if (m_enable_data_field_) {
            m_field_data_["Fields"].push_back(data_field_data);
        }
        
        m_data_["fields"].push_back(field_data);
    }
    
    void BitwardenGenericItem::removeFieldImpl(const Botan::secure_vector<uint8_t>& name) {
        if (!m_init) {
            return;
        }

        if (!m_data_.contains("fields") || !m_data_["fields"].is_array()) {
            m_data_["fields"] = nlohmann::json::array();
        }

        if (m_enable_data_field_ && (!m_field_data_.contains("Fields") || 
            !m_field_data_["Fields"].is_array())) {
            m_field_data_["fields"] = nlohmann::json::array();
        }

        std::erase_if(m_data_["fields"], [&](nlohmann::json field) {
            if (!field.contains("name") || !field["name"].is_string()) {
                return false;
            }

            std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> field_name_err = 
                m_vault.getOrchestrator()->getCrypto()->decrypt(field["name"], m_item_keys);
            
            if (!field_name_err.has_value()) {
                return false;
            }

            return field_name_err.value() == name;
        });

        if (m_enable_data_field_) {
            std::erase_if(m_field_data_["Fields"], [&](nlohmann::json field) {
                if (!field.contains("Name") || !field["Name"].is_string()) {
                    return false;
                }

                std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> field_name_err = 
                    m_vault.getOrchestrator()->getCrypto()->decrypt(field["Name"], m_item_keys);
                
                if (!field_name_err.has_value()) {
                    return false;
                }

                return field_name_err.value() == name;
            });
        }
    }
    
    void BitwardenGenericItem::clearFieldsImpl() {
        m_data_["fields"] = nlohmann::json::array();
        m_field_data_["fields"] = nlohmann::json::array();
    }
    
    void BitwardenGenericItem::getNameImpl(Botan::secure_vector<uint8_t>& o_name) {
        if (!m_init) {
            return;
        }

        if (!m_data_.contains("name") || !m_data_["name"].is_string()) {
            return;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->decrypt(m_data_["name"], m_item_keys);
        
        if (!value_err.has_value()) {
            return;
        }
        
        o_name = std::move(value_err.value());
    }
    
    void BitwardenGenericItem::getNotesImpl(Botan::secure_vector<uint8_t>& o_notes) {
        if (!m_init) {
            return;
        }

        if (!m_data_.contains("notes") || !m_data_["notes"].is_string()) {
            return;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->decrypt(m_data_["notes"], m_item_keys);
        
        if (!value_err.has_value()) {
            return;
        }
        
        o_notes = std::move(value_err.value());
    }
    
    void BitwardenGenericItem::getGroupsImpl(std::vector<ItemId>& o_group_ids) {
        if (!m_init) {
            return;
        }

        o_group_ids.clear();

        if (!m_data_.contains("folderId") || !m_data_["folderId"].is_string()) {
            return;
        }
        
        o_group_ids.push_back(m_data_["folderId"]);
    }
    
    void BitwardenGenericItem::getFieldsImpl(std::vector<CustomField>& o_fields) {
        if (!m_init) {
            return;
        }

        if (!m_data_.contains("fields") || !m_data_["fields"].is_array()) {
            return;
        }

        o_fields.clear();

        for (nlohmann::json json_field : m_data_["fields"]) {
            if (!json_field.contains("name") || !json_field["name"].is_string() ||
                !json_field.contains("value") || !json_field["value"].is_string() ||
                !json_field.contains("type") || !json_field["type"].is_number_integer()) {
                continue;
            }

            CustomField field;
            field.type = static_cast<CustomFieldType>(json_field["type"]);

            std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> name_err = 
                m_vault.getOrchestrator()->getCrypto()->decrypt(json_field["name"], m_item_keys);
            
            if (!name_err.has_value()) {
                continue;
            }

            field.name = std::move(name_err.value());

            if (field.type == CustomFieldType::Linked) {
                field.value = utils::getSecureVector(std::to_string(json_field["linkedId"]));
            } else {
                std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
                    m_vault.getOrchestrator()->getCrypto()->decrypt(json_field["value"], m_item_keys);
                
                if (!value_err.has_value()) {
                    continue;
                }

                field.value = std::move(value_err.value());
            }

            o_fields.push_back(std::move(field));
        }
    }
    
    void BitwardenGenericItem::getIdImpl(ItemId& o_id) {
        if (!m_init) {
            return;
        }

        o_id = m_id;
    }
    
    void BitwardenGenericItem::getCreationImpl(std::string& o_time) {
        if (!m_init) {
            return;
        }

        if (!m_data_.contains("creationDate") || !m_data_["creationDate"].is_string()) {
            return;
        }

        o_time = m_data_["creationDate"];
    }
    
    void BitwardenGenericItem::getModificationImpl(std::string& o_time) {
        if (!m_init) {
            return;
        }

        Entity entity;
        entity.type = EntityType::Item;
        entity.id = m_id;

        std::expected<PendingChange, RuntimeError> record_err = 
            m_vault.getOrchestrator()->getRuntime()->getRecord(entity);
        
        if (record_err.has_value() && record_err.value().type == ChangeType::Updated) {
            o_time = record_err.value().revision_date;
            return;
        }

        if (!m_data_.contains("revisionDate") || !m_data_["revisionDate"].is_string()) {
            return;
        }

        o_time = m_data_["revisionDate"];
    }
    
    void BitwardenGenericItem::getDeletionImpl(std::string& o_time) {
        if (!m_init) {
            return;
        }

        if (!m_data_.contains("deletedDate") || !m_data_["deletedDate"].is_string()) {
            return;
        }

        o_time = m_data_["deletedDate"];
    }
    
    void BitwardenGenericItem::addAttachmentImpl(const Botan::secure_vector<uint8_t>& name, 
        const Botan::secure_vector<uint8_t>& content, ItemId& o_id,
        std::function<void(float)> on_progress) {
        std::expected<Botan::secure_vector<uint8_t>, OrchestratorError> attachment_err = 
            m_vault.getOrchestrator()->addAttachment(m_id, content, name, on_progress);
        
        if (!attachment_err.has_value()) {
            return;
        }

        o_id = utils::getString(attachment_err.value());
    }
    
    /**
     * @note We can't really do anything if it error's out anyway, so we don't need to check for
     *  errors here.
     */
    void BitwardenGenericItem::downloadAttachmentImpl(const ItemId& id, const std::filesystem::path& path,
        std::function<void(float)> on_progress) {
        OrchestratorError attachment_err = m_vault.getOrchestrator()->downloadAttachment(
            m_id, utils::getSecureVector(id), path, on_progress);
    }
    
    void BitwardenGenericItem::getAttachmentIdsImpl(std::vector<ItemId>& o_ids) {
        if (!m_init) {
            return;
        }

        if (!m_data_.contains("attachments") || !m_data_["attachments"].is_array()) {
            return;
        }

        o_ids.clear();

        for (nlohmann::json attachment : m_data_["attachments"]) {
            if (!attachment.is_object() || !attachment.contains("id") ||
                !attachment["id"].is_string()) {
                continue;
            }
            
            o_ids.push_back(attachment["id"]);
        }
    }
    
    void BitwardenGenericItem::getAttachmentNameImpl(const ItemId& id, Botan::secure_vector<uint8_t>& o_name) {
        if (!m_init) {
            return;
        }

        if (!m_data_.contains("attachments") || !m_data_["attachments"].is_array()) {
            return;
        }

        for (nlohmann::json attachment : m_data_["attachments"]) {
            if (!attachment.is_object() || !attachment.contains("id") ||
                !attachment["id"].is_string() || !attachment.contains("fileName") ||
                !attachment["fileName"].is_string()) {
                continue;
            }

            if (attachment["id"] != id) {
                continue;
            }

            std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> name_err = 
                m_vault.getOrchestrator()->getCrypto()->decrypt(attachment["fileName"], m_item_keys);
            
            if (!name_err.has_value()) {
                continue;
            }
            
            o_name = std::move(name_err.value());
            return;
        }
    }
    
    void BitwardenGenericItem::removeAttachmentImpl(const ItemId& id) {
        if (!m_init) {
            return;
        }

        if (!m_data_.contains("attachments") || !m_data_["attachments"].is_array()) {
            return;
        }

        std::erase_if(m_data_["attachments"], [&](nlohmann::json attachment) {
            if (!attachment.contains("id") || !attachment["id"].is_string()) {
                return false;
            }

            return attachment["id"] == id;
        });
    }
    
    void BitwardenGenericItem::setFavoriteImpl(bool value) {
        if (!m_init) {
            return;
        }

        m_data_["favorite"] = value;
    }
    
    void BitwardenGenericItem::setRepromptImpl(bool value) {
        if (!m_init) {
            return;
        }

        m_data_["reprompt"] = value ? 1 : 0;
    }
    
    void BitwardenGenericItem::getFavoriteImpl(bool& o_value) {
        if (!m_init) {
            return;
        }

        if (!m_data_.contains("favorite") || !m_data_["favorite"].is_boolean()) {
            return;
        }

        o_value = m_data_["favorite"];
    }
    
    void BitwardenGenericItem::getRepromptImpl(bool& o_value) {
        if (!m_init) {
            return;
        }

        if (!m_data_.contains("reprompt") || !m_data_["reprompt"].is_number_integer()) {
            return;
        }

        o_value = (m_data_["reprompt"] == 1) ? true : false;
    }
    
    void BitwardenGenericItem::getTypeImpl(ItemType& o_value) {
        if (!m_init) {
            return;
        }

        if (!m_data_.contains("type") || !m_data_["type"].is_number_integer()) {
            return;
        }

        o_value = static_cast<ItemType>(m_data_["type"]);
    }
}