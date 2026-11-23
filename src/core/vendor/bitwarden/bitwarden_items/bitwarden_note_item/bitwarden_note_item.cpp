#include "bitwarden_note_item.h"

namespace clientwarden::vendor::bitwarden {
    BitwardenNoteItem::BitwardenNoteItem(Vault& vault, ItemId id, bool item_creation)
     : GenericItemImpl<BitwardenGenericItem, BitwardenNoteItem>(vault, id, item_creation) {
        if (!item_creation) {
            if (!m_data_.contains("secureNote") || !m_data_["secureNote"].is_object() ||
                !m_data_.contains("type") || !m_data_["type"].is_number_integer() ||
                m_data_["type"] != std::to_underlying(ItemType::Note)) {
                m_init = false;
            } else {
                m_init = true;
            }
        } else {
            m_init = false;

            std::expected<ItemKey, CryptoErrors> key_err = 
                m_vault.getOrchestrator()->getCrypto()->generateKey();
            
            if (!key_err.has_value()) {
                return;
            }

            m_item_keys = std::move(key_err.value());

            std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> unres_key_err = 
                m_vault.getOrchestrator()->getCrypto()->generateUnresolvedKey(m_item_keys);
            
            if (!unres_key_err.has_value()) {
                return;
            }

            std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> name_err = 
                m_vault.getOrchestrator()->getCrypto()->encrypt(utils::getSecureVector(""), 
                    m_item_keys);
            
            if (!name_err.has_value()) {
                return;
            }

            if (m_enable_data_field_) {
                m_field_data_["Fields"] = nlohmann::json::array();
                m_field_data_["Name"] = utils::getString(name_err.value());
                m_field_data_["Notes"] = nullptr;
            }

            m_data_["archivedDate"] = nullptr;
            m_data_["attachments"] = nullptr;
            m_data_["card"] = nullptr;
            m_data_["collectionIds"] = nlohmann::json::array();
            m_data_["creationDate"] = utils::s_getCurrentTime();

            if (m_enable_data_field_) {
                m_data_["data"] = "{}";
            }

            m_data_["deletedDate"] = nullptr;
            m_data_["edit"] = true;
            m_data_["favorite"] = false;
            m_data_["fields"] = nlohmann::json::array();
            m_data_["folderId"] = nullptr;
            m_data_["id"] = utils::getUniqueId();
            m_data_["identity"] = nullptr;
            m_data_["key"] = utils::getString(std::move(unres_key_err.value()));
            m_data_["login"] = nullptr;
            m_data_["name"] = utils::getString(std::move(name_err.value()));
            m_data_["notes"] = nullptr;
            m_data_["object"] = "cipherDetails";
            m_data_["organizationId"] = nullptr;
            m_data_["organizationUseTotp"] = nullptr;
            m_data_["passwordHistory"] = nlohmann::json::array();
            m_data_["permissions"] = nlohmann::json::object();
            m_data_["permissions"]["delete"] = true;
            m_data_["permissions"]["restore"] = true;
            m_data_["reprompt"] = 0;

            if (m_enable_bank_account_field_) {
                m_data_["bankAccount"] = nullptr;
            }
            if (m_enable_passport_field_) {
                m_data_["passport"] = nullptr;
            }
            if (m_enable_drivers_license_field_) {
                m_data_["driversLicense"] = nullptr;
            }
            
            m_data_["revisionDate"] = utils::s_getCurrentTime();
            m_data_["secureNote"] = nlohmann::json::object();
            m_data_["secureNote"]["type"] = 0;
            m_data_["sshKey"] = nullptr;
            m_data_["type"] = std::to_underlying(ItemType::Note);
            m_data_["viewPassword"] = true;

            m_init = true;
        }
    }
    
    BitwardenNoteItem* BitwardenNoteItem::duplicate(ItemId& o_id) {
        std::expected<ItemKey, CryptoErrors> key_err = 
            m_vault.getOrchestrator()->getCrypto()->generateKey();
            
        if (!key_err.has_value()) {
            return this;
        }

        nlohmann::json new_data;
        nlohmann::json new_field_data;
        
        Botan::secure_vector<uint8_t> old_name;
        Botan::secure_vector<uint8_t> old_notes;
        std::vector<CustomField> old_fields;

        getName(old_name);
        getNotes(old_notes);
        getFields(old_fields);

        Botan::secure_vector<uint8_t> new_name;
        Botan::secure_vector<uint8_t> new_notes;

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> unres_key_err = 
            m_vault.getOrchestrator()->getCrypto()->generateUnresolvedKey(key_err.value());
            
        if (!unres_key_err.has_value()) {
            return this;
        }

        /**
         * @note Set the Name.
         */
        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->encrypt(old_name, key_err.value());
            
        if (!value_err.has_value()) {
            return this;
        }

        new_name = std::move(value_err.value());

        /**
         * @note Set the Notes.
         */
        value_err = m_vault.getOrchestrator()->getCrypto()->encrypt(old_notes, key_err.value());
            
        if (!value_err.has_value()) {
            return this;
        }

        new_notes = std::move(value_err.value());

        if (m_enable_data_field_) {
            new_field_data["Fields"] = nlohmann::json::array();
            new_field_data["Name"] = utils::getString(new_name);
            new_field_data["Notes"] = utils::getString(new_notes);
        }

        new_data["archivedDate"] = m_data_["archivedDate"];
        new_data["attachments"] = nullptr;
        new_data["card"] = nullptr;
        new_data["collectionIds"] = m_data_["collectionIds"];
        new_data["creationDate"] = utils::s_getCurrentTime();

        if (m_enable_data_field_) {
            new_data["data"] = new_field_data;
        }

        new_data["deletedDate"] = m_data_["deletedDate"];
        new_data["edit"] = m_data_["edit"];
        new_data["favorite"] = m_data_["favorite"];
        new_data["fields"] = nlohmann::json::array();
        new_data["folderId"] = m_data_["folderId"];
        new_data["id"] = utils::getUniqueId();
        new_data["identity"] = nullptr;
        new_data["key"] = utils::getString(std::move(unres_key_err.value()));
        new_data["login"] = nullptr;
        new_data["name"] = utils::getString(new_name);
        new_data["notes"] = utils::getString(new_notes);
        new_data["object"] = "cipherDetails";
        new_data["organizationId"] = nullptr;
        new_data["organizationUseTotp"] = nullptr;
        new_data["passwordHistory"] = nlohmann::json::array();
        new_data["permissions"] = m_data_["permissions"];
        new_data["reprompt"] = m_data_["reprompt"];

        if (m_enable_bank_account_field_) {
            new_data["bankAccount"] = nullptr;
        }
        if (m_enable_passport_field_) {
            new_data["passport"] = nullptr;
        }
        if (m_enable_drivers_license_field_) {
            new_data["driversLicense"] = nullptr;
        }
            
        new_data["revisionDate"] = utils::s_getCurrentTime();
        new_data["secureNote"] = nlohmann::json::object();
        new_data["secureNote"]["type"] = 0;
        new_data["sshKey"] = nullptr;
        new_data["type"] = std::to_underlying(ItemType::Note);
        new_data["viewPassword"] = m_data_["viewPassword"];

        /**
         * @note Set the CustomFields.
         */
        for (CustomField& field : old_fields) {
            nlohmann::json custom_data;
            nlohmann::json custom_data_field;

            custom_data["type"] = std::to_underlying(field.type);
            custom_data_field["Type"] = std::to_underlying(field.type);

            value_err = m_vault.getOrchestrator()->getCrypto()->encrypt(field.name, 
                key_err.value());
            
            if (!value_err.has_value()) {
                Botan::secure_scrub_memory(field.name.data(), field.name.size());
                Botan::secure_scrub_memory(field.value.data(), field.value.size());
                continue;
            }

            custom_data_field["Name"] = utils::getString(value_err.value());
            custom_data["name"] = utils::getString(std::move(value_err.value()));

            if (field.type == CustomFieldType::Linked) {
                custom_data_field["LinkedId"] = utils::getString(field.value);
                custom_data["linkedId"] = utils::getString(field.value);
                custom_data["value"] = nullptr;
            } else {
                value_err = m_vault.getOrchestrator()->getCrypto()->encrypt(field.value, 
                    key_err.value());
                
                if (!value_err.has_value()) {
                    Botan::secure_scrub_memory(field.name.data(), field.name.size());
                    Botan::secure_scrub_memory(field.value.data(), field.value.size());
                    continue;
                }

                custom_data_field["Value"] = utils::getString(value_err.value());
                custom_data["value"] = utils::getString(std::move(value_err.value()));
                custom_data["linkedId"] = nullptr;
            }

            if (m_enable_data_field_) {
                new_field_data["Fields"].push_back(std::move(custom_data_field));
            }

            new_data["fields"].push_back(std::move(custom_data));

            Botan::secure_scrub_memory(field.name.data(), field.name.size());
            Botan::secure_scrub_memory(field.value.data(), field.value.size());
        }

        Botan::secure_scrub_memory(old_name.data(), old_name.size());
        Botan::secure_scrub_memory(old_notes.data(), old_notes.size());
        Botan::secure_scrub_memory(new_name.data(), new_name.size());
        Botan::secure_scrub_memory(new_notes.data(), new_notes.size());
        
        key_err.value().clear();

        if (m_enable_data_field_) {
            new_data["data"] = new_field_data.dump();
        }

        /**
         * @note We dont need to check this, bc if it fails, it'll be created at the next sync.
         */
        OrchestratorError action_err = 
            m_vault.getOrchestrator()->newItem(new_data);
            
        o_id = new_data["id"];

        return this;
    }
    
    BitwardenNoteItem* BitwardenNoteItem::getType(ItemType& val) {
        val = ItemType::Note;
        return this;
    }
}