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
                if (nlohmann::json::accept(m_data_["data"])) {
                    m_field_data_ = nlohmann::json::parse(m_data_["data"]);
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

        if (m_enable_data_field_) {
            m_data_["data"] = m_field_data_.dump();
        }

        OrchestratorError action_err = 
            m_vault.getOrchestrator()->updateItem(m_data_);
        
        if (!action_err.has_value()) {
            return std::unexpected(ItemError::OrchestratorError);
        }

        m_item_keys.clear();
        m_init = false;

        return {};
    }
    
    std::expected<void, ItemError> BitwardenGenericItem::deleteItem() {
        if (!m_init) {
            return std::unexpected(ItemError::Uninitialised);
        }

        OrchestratorError action_err = 
            m_vault.getOrchestrator()->deleteItem(m_id);
        
        if (!action_err.has_value()) {
            return std::unexpected(ItemError::OrchestratorError);
        }

        m_item_keys.clear();
        m_init = false;

        return {};
    }
    
    std::expected<void, ItemError> BitwardenGenericItem::binItem() {
        if (!m_init) {
            return std::unexpected(ItemError::Uninitialised);
        }

        if (m_enable_data_field_) {
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

        m_item_keys.clear();
        m_init = false;

        return {};
    }
    
    std::expected<void, ItemError> BitwardenGenericItem::unBinItem() {
        if (!m_init) {
            return std::unexpected(ItemError::Uninitialised);
        }

        if (m_enable_data_field_) {
            m_data_["data"] = m_field_data_.dump();
        }

        OrchestratorError action_err = 
            m_vault.getOrchestrator()->updateItem(m_data_);

        OrchestratorError action_extra_err = 
            m_vault.getOrchestrator()->restoreItem(m_id);
        
        if (!action_err.has_value() || !action_extra_err.has_value()) {
            return std::unexpected(ItemError::OrchestratorError);
        }

        m_item_keys.clear();
        m_init = false;

        return {};
    }
    
    std::expected<void, ItemError> BitwardenGenericItem::archiveItem() {
        if (!m_init) {
            return std::unexpected(ItemError::Uninitialised);
        }

        if (m_enable_data_field_) {
            m_data_["data"] = m_field_data_.dump();
        }

        OrchestratorError action_err = 
            m_vault.getOrchestrator()->updateItem(m_data_);

        OrchestratorError action_extra_err = 
            m_vault.getOrchestrator()->archiveItem(m_id);
        
        if (!action_err.has_value() || !action_extra_err.has_value()) {
            return std::unexpected(ItemError::OrchestratorError);
        }

        m_item_keys.clear();
        m_init = false;

        return {};
    }
    
    std::expected<void, ItemError> BitwardenGenericItem::unArchiveItem() {
        if (!m_init) {
            return std::unexpected(ItemError::Uninitialised);
        }

        if (m_enable_data_field_) {
            m_data_["data"] = m_field_data_.dump();
        }

        OrchestratorError action_err = 
            m_vault.getOrchestrator()->updateItem(m_data_);

        OrchestratorError action_extra_err = 
            m_vault.getOrchestrator()->unArchiveItem(m_id);
        
        if (!action_err.has_value() || !action_extra_err.has_value()) {
            return std::unexpected(ItemError::OrchestratorError);
        }

        m_item_keys.clear();
        m_init = false;

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
            m_data["folderId"] = group_ids[0];
        }
    }
    
    void BitwardenGenericItem::addGroupImpl(const ItemId& group_id) {
        if (!m_init) {
            return;
        }

        if (group_id == "" || group_id == "00000000-0000-0000-0000-000000000000") {
            m_data_["folderId"] = nullptr;
        } else {
            m_data["folderId"] = group_id;
        }
    }
    
    void BitwardenGenericItem::removeGroupImpl(const ItemId& group_id) {
        if (!m_init) {
            return;
        }

        m_data_["folderId"] = nullptr;
    }
    
    void BitwardenGenericItem::addFieldImpl(const CustomField& field) {
        
    }
    
    void BitwardenGenericItem::removeFieldImpl(const Botan::secure_vector<uint8_t>& name) {
        
    }
    
    void BitwardenGenericItem::clearFieldsImpl() {
        
    }
    
    void BitwardenGenericItem::getNameImpl(Botan::secure_vector<uint8_t>& o_name) {
        
    }
    
    void BitwardenGenericItem::getNotesImpl(Botan::secure_vector<uint8_t>& o_name) {
        
    }
    
    void BitwardenGenericItem::getGroupsImpl(std::vector<ItemId>& o_group_ids) {
        
    }
    
    void BitwardenGenericItem::getFieldsImpl(std::vector<CustomField>& o_fields) {
        
    }
    
    void BitwardenGenericItem::getIdImpl(ItemId& o_id) {
        
    }
    
    void BitwardenGenericItem::getCreationImpl(std::string& o_time) {
        
    }
    
    void BitwardenGenericItem::getModificationImpl(std::string& o_time) {
        
    }
    
    void BitwardenGenericItem::getDeletionImpl(std::string& o_time) {
        
    }
    
    void BitwardenGenericItem::addAttachmentImpl(const Botan::secure_vector<uint8_t>& name, 
        const Botan::secure_vector<uint8_t>& content, ItemId& o_id,
        std::function<void(float)> on_progress) {
        
    }
    
    void BitwardenGenericItem::downloadAttachmentImpl(const ItemId& id, const std::filesystem::path& path,
        std::function<void(float)> on_progress) {
        
    }
    
    void BitwardenGenericItem::getAttachmentIdsImpl(std::vector<ItemId>& o_ids) {
        
    }
    
    void BitwardenGenericItem::getAttachmentNameImpl(const ItemId& id, Botan::secure_vector<uint8_t>& o_name) {
        
    }
    
    void BitwardenGenericItem::removeAttachmentImpl(const ItemId& id) {
        
    }
    
    void BitwardenGenericItem::setFavoriteImpl(bool value) {
        
    }
    
    void BitwardenGenericItem::setRepromptImpl(bool value) {
        
    }
    
    void BitwardenGenericItem::getFavoriteImpl(bool& o_value) {
        
    }
    
    void BitwardenGenericItem::getRepromptImpl(bool& o_value) {
        
    }
    
    void BitwardenGenericItem::getTypeImpl(ItemType& o_value) {
        
    }
    
}