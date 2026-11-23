#include "bitwarden_card_item.h"

namespace clientwarden::vendor::bitwarden {
    BitwardenCardItem::BitwardenCardItem(Vault& vault, ItemId id, bool item_creation)
     : GenericItemImpl<BitwardenGenericItem, BitwardenCardItem>(vault, id, item_creation) {
        if (!item_creation) {
            if (!m_data_.contains("card") || !m_data_["card"].is_object() ||
                !m_data_.contains("type") || !m_data_["type"].is_number_integer() ||
                m_data_["type"] != std::to_underlying(ItemType::Card)) {
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
                m_field_data_["CardholderName"] = nullptr;
                m_field_data_["Brand"] = nullptr;
                m_field_data_["Number"] = nullptr;
                m_field_data_["ExpMonth"] = nullptr;
                m_field_data_["ExpYear"] = nullptr;
                m_field_data_["Code"] = nullptr;
            }

            m_data_["archivedDate"] = nullptr;
            m_data_["attachments"] = nullptr;
            m_data_["card"] = nlohmann::json::object();
            m_data_["card"]["brand"] = nullptr;
            m_data_["card"]["cardholderName"] = nullptr;
            m_data_["card"]["code"] = nullptr;
            m_data_["card"]["expMonth"] = nullptr;
            m_data_["card"]["expYear"] = nullptr;
            m_data_["card"]["number"] = nullptr;
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
            m_data_["secureNote"] = nullptr;
            m_data_["sshKey"] = nullptr;
            m_data_["type"] = std::to_underlying(ItemType::Card);
            m_data_["viewPassword"] = true;

            m_init = true;
        }
    }
    
    BitwardenCardItem* BitwardenCardItem::setBrand(const Botan::secure_vector<uint8_t>& brand) {
        if (!m_init || !m_data_.contains("card") ||
            !m_data_["card"].is_object()) {
            return this;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->encrypt(brand, m_item_keys);
        
        if (!value_err.has_value()) {
            return this;
        }

        std::string value = utils::getString(value_err.value());

        if (m_enable_data_field_) {
            m_field_data_["Brand"] = value;
        }

        m_data_["card"]["brand"] = std::move(value);

        return this;
    }
    
    BitwardenCardItem* BitwardenCardItem::setCardholderName(
        const Botan::secure_vector<uint8_t>& cardholder_name) {
        if (!m_init || !m_data_.contains("card") ||
            !m_data_["card"].is_object()) {
            return this;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->encrypt(cardholder_name, m_item_keys);
        
        if (!value_err.has_value()) {
            return this;
        }

        std::string value = utils::getString(value_err.value());

        if (m_enable_data_field_) {
            m_field_data_["CardholderName"] = value;
        }

        m_data_["card"]["cardholderName"] = std::move(value);

        return this;
    }
    
    BitwardenCardItem* BitwardenCardItem::setCode(const Botan::secure_vector<uint8_t>& code) {
        if (!m_init || !m_data_.contains("card") ||
            !m_data_["card"].is_object()) {
            return this;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->encrypt(code, m_item_keys);
        
        if (!value_err.has_value()) {
            return this;
        }

        std::string value = utils::getString(value_err.value());

        if (m_enable_data_field_) {
            m_field_data_["Code"] = value;
        }

        m_data_["card"]["code"] = std::move(value);

        return this;
    }
    
    BitwardenCardItem* BitwardenCardItem::setExpMonth(
        const Botan::secure_vector<uint8_t>& exp_month) {
        if (!m_init || !m_data_.contains("card") ||
            !m_data_["card"].is_object()) {
            return this;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->encrypt(exp_month, m_item_keys);
        
        if (!value_err.has_value()) {
            return this;
        }

        std::string value = utils::getString(value_err.value());

        if (m_enable_data_field_) {
            m_field_data_["ExpMonth"] = value;
        }

        m_data_["card"]["expMonth"] = std::move(value);

        return this;
    }
    
    BitwardenCardItem* BitwardenCardItem::setExpYear(
        const Botan::secure_vector<uint8_t>& exp_year) {
        if (!m_init || !m_data_.contains("card") ||
            !m_data_["card"].is_object()) {
            return this;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->encrypt(exp_year, m_item_keys);
        
        if (!value_err.has_value()) {
            return this;
        }

        std::string value = utils::getString(value_err.value());

        if (m_enable_data_field_) {
            m_field_data_["ExpYear"] = value;
        }

        m_data_["card"]["expYear"] = std::move(value);

        return this;
    }
    
    BitwardenCardItem* BitwardenCardItem::setNumber(
        const Botan::secure_vector<uint8_t>& number) {
        if (!m_init || !m_data_.contains("card") ||
            !m_data_["card"].is_object()) {
            return this;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->encrypt(number, m_item_keys);
        
        if (!value_err.has_value()) {
            return this;
        }

        std::string value = utils::getString(value_err.value());

        if (m_enable_data_field_) {
            m_field_data_["Number"] = value;
        }

        m_data_["card"]["number"] = std::move(value);

        return this;
    }
    
    BitwardenCardItem* BitwardenCardItem::duplicate(ItemId& o_id) {
        std::expected<ItemKey, CryptoErrors> key_err = 
            m_vault.getOrchestrator()->getCrypto()->generateKey();
            
        if (!key_err.has_value()) {
            return this;
        }

        nlohmann::json new_data;
        nlohmann::json new_field_data;
        
        Botan::secure_vector<uint8_t> old_name;
        Botan::secure_vector<uint8_t> old_brand;
        Botan::secure_vector<uint8_t> old_cardholder_name;
        Botan::secure_vector<uint8_t> old_code;
        Botan::secure_vector<uint8_t> old_exp_month;
        Botan::secure_vector<uint8_t> old_exp_year;
        Botan::secure_vector<uint8_t> old_number;
        Botan::secure_vector<uint8_t> old_notes;
        std::vector<CustomField> old_fields;

        getName(old_name);
        getBrand(old_brand);
        getCardholderName(old_cardholder_name);
        getCode(old_code);
        getExpMonth(old_exp_month);
        getExpYear(old_exp_year);
        getNumber(old_number);
        getNotes(old_notes);
        getFields(old_fields);

        Botan::secure_vector<uint8_t> new_name;
        Botan::secure_vector<uint8_t> new_brand;
        Botan::secure_vector<uint8_t> new_cardholder_name;
        Botan::secure_vector<uint8_t> new_code;
        Botan::secure_vector<uint8_t> new_exp_month;
        Botan::secure_vector<uint8_t> new_exp_year;
        Botan::secure_vector<uint8_t> new_number;
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
         * @note Set the Brand.
         */
        value_err = m_vault.getOrchestrator()->getCrypto()->encrypt(old_brand, key_err.value());
            
        if (!value_err.has_value()) {
            return this;
        }

        new_brand = std::move(value_err.value());

        /**
         * @note Set the Cardholder Name.
         */
        value_err = m_vault.getOrchestrator()->getCrypto()->encrypt(old_cardholder_name, 
            key_err.value());
            
        if (!value_err.has_value()) {
            return this;
        }

        new_cardholder_name = std::move(value_err.value());

        /**
         * @note Set the Code.
         */
        value_err = m_vault.getOrchestrator()->getCrypto()->encrypt(old_code, key_err.value());
            
        if (!value_err.has_value()) {
            return this;
        }

        new_code = std::move(value_err.value());

        /**
         * @note Set the Exp Month.
         */
        value_err = m_vault.getOrchestrator()->getCrypto()->encrypt(old_exp_month, key_err.value());
            
        if (!value_err.has_value()) {
            return this;
        }

        new_exp_month = std::move(value_err.value());

        /**
         * @note Set the Exp Year.
         */
        value_err = m_vault.getOrchestrator()->getCrypto()->encrypt(old_exp_year, key_err.value());
            
        if (!value_err.has_value()) {
            return this;
        }

        new_exp_year = std::move(value_err.value());

        /**
         * @note Set the Number.
         */
        value_err = m_vault.getOrchestrator()->getCrypto()->encrypt(old_number, key_err.value());
            
        if (!value_err.has_value()) {
            return this;
        }

        new_number = std::move(value_err.value());

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
            new_field_data["CardholderName"] = utils::getString(new_cardholder_name);
            new_field_data["Brand"] = utils::getString(new_brand);
            new_field_data["Number"] = utils::getString(new_number);
            new_field_data["ExpMonth"] = utils::getString(new_exp_month);
            new_field_data["ExpYear"] = utils::getString(new_exp_year);
            new_field_data["Code"] = utils::getString(new_code);
        }

        new_data["archivedDate"] = m_data_["archivedDate"];
        new_data["attachments"] = nullptr;
        new_data["card"] = nlohmann::json::object();
        new_data["card"]["brand"] = utils::getString(new_brand);
        new_data["card"]["cardholderName"] = utils::getString(new_cardholder_name);
        new_data["card"]["code"] = utils::getString(new_code);
        new_data["card"]["expMonth"] = utils::getString(new_exp_month);
        new_data["card"]["expYear"] = utils::getString(new_exp_year);
        new_data["card"]["number"] = utils::getString(new_number);
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
        new_data["secureNote"] = nullptr;
        new_data["sshKey"] = nullptr;
        new_data["type"] = std::to_underlying(ItemType::Card);
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
        Botan::secure_scrub_memory(old_brand.data(), old_brand.size());
        Botan::secure_scrub_memory(old_cardholder_name.data(), old_cardholder_name.size());
        Botan::secure_scrub_memory(old_code.data(), old_code.size());
        Botan::secure_scrub_memory(old_exp_month.data(), old_exp_month.size());
        Botan::secure_scrub_memory(old_exp_year.data(), old_exp_year.size());
        Botan::secure_scrub_memory(old_number.data(), old_number.size());
        Botan::secure_scrub_memory(old_notes.data(), old_notes.size());
        Botan::secure_scrub_memory(new_name.data(), new_name.size());
        Botan::secure_scrub_memory(new_brand.data(), new_brand.size());
        Botan::secure_scrub_memory(new_cardholder_name.data(), new_cardholder_name.size());
        Botan::secure_scrub_memory(new_code.data(), new_code.size());
        Botan::secure_scrub_memory(new_exp_month.data(), new_exp_month.size());
        Botan::secure_scrub_memory(new_exp_year.data(), new_exp_year.size());
        Botan::secure_scrub_memory(new_number.data(), new_number.size());
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
    
    BitwardenCardItem* BitwardenCardItem::getBrand(Botan::secure_vector<uint8_t>& brand) {
        if (!m_init || !m_data_.contains("card") ||
            !m_data_["card"].is_object() || !m_data_["card"].contains("brand") ||
            !m_data_["card"]["brand"].is_string()) {
            brand.clear();
            return this;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->decrypt(m_data_["card"]["brand"], m_item_keys);
        
        if (!value_err.has_value()) {
            return this;
        }

        brand = std::move(value_err.value());

        return this;
    }
    
    BitwardenCardItem* BitwardenCardItem::getCardholderName(
        Botan::secure_vector<uint8_t>& cardholder_name) {
        if (!m_init || !m_data_.contains("card") ||
            !m_data_["card"].is_object() || !m_data_["card"].contains("cardholderName") ||
            !m_data_["card"]["cardholderName"].is_string()) {
            cardholder_name.clear();
            return this;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->decrypt(m_data_["card"]["cardholderName"], 
                m_item_keys);
        
        if (!value_err.has_value()) {
            return this;
        }

        cardholder_name = std::move(value_err.value());

        return this;
    }
    
    BitwardenCardItem* BitwardenCardItem::getCode(Botan::secure_vector<uint8_t>& code) {
        if (!m_init || !m_data_.contains("card") ||
            !m_data_["card"].is_object() || !m_data_["card"].contains("code") ||
            !m_data_["card"]["code"].is_string()) {
            code.clear();
            return this;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->decrypt(m_data_["card"]["code"], m_item_keys);
        
        if (!value_err.has_value()) {
            return this;
        }

        code = std::move(value_err.value());

        return this;
    }
    
    BitwardenCardItem* BitwardenCardItem::getExpMonth(Botan::secure_vector<uint8_t>& exp_month) {
        if (!m_init || !m_data_.contains("card") ||
            !m_data_["card"].is_object() || !m_data_["card"].contains("expMonth") ||
            !m_data_["card"]["expMonth"].is_string()) {
            exp_month.clear();
            return this;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->decrypt(m_data_["card"]["expMonth"], 
                m_item_keys);
        
        if (!value_err.has_value()) {
            return this;
        }

        exp_month = std::move(value_err.value());

        return this;
    }
    
    BitwardenCardItem* BitwardenCardItem::getExpYear(Botan::secure_vector<uint8_t>& exp_year) {
        if (!m_init || !m_data_.contains("card") ||
            !m_data_["card"].is_object() || !m_data_["card"].contains("expYear") ||
            !m_data_["card"]["expYear"].is_string()) {
            exp_year.clear();
            return this;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->decrypt(m_data_["card"]["expYear"], 
                m_item_keys);
        
        if (!value_err.has_value()) {
            return this;
        }

        exp_year = std::move(value_err.value());

        return this;
    }
    
    BitwardenCardItem* BitwardenCardItem::getNumber(Botan::secure_vector<uint8_t>& number) {
        if (!m_init || !m_data_.contains("card") ||
            !m_data_["card"].is_object() || !m_data_["card"].contains("number") ||
            !m_data_["card"]["number"].is_string()) {
            number.clear();
            return this;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->decrypt(m_data_["card"]["number"], 
                m_item_keys);
        
        if (!value_err.has_value()) {
            return this;
        }

        number = std::move(value_err.value());

        return this;
    }
    
    BitwardenCardItem* BitwardenCardItem::getType(ItemType& val) {
        val = ItemType::Card;
        return this;
    }
}