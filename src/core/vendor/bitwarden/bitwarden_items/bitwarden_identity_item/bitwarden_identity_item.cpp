#include "bitwarden_identity_item.h"

namespace clientwarden::vendor::bitwarden {
    BitwardenIdentityItem::BitwardenIdentityItem(Vault& vault, ItemId id, bool item_creation)
     : GenericItemImpl<BitwardenGenericItem, BitwardenIdentityItem>(vault, id, item_creation) {
        if (!item_creation) {
            if (!m_data_.contains("identity") || !m_data_["identity"].is_object() ||
                !m_data_.contains("type") || !m_data_["type"].is_number_integer() ||
                m_data_["type"] != std::to_underlying(ItemType::Identity)) {
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
                m_field_data_["Title"] = nullptr;
                m_field_data_["FirstName"] = nullptr;
                m_field_data_["MiddleName"] = nullptr;
                m_field_data_["LastName"] = nullptr;
                m_field_data_["Address1"] = nullptr;
                m_field_data_["Address2"] = nullptr;
                m_field_data_["Address3"] = nullptr;
                m_field_data_["City"] = nullptr;
                m_field_data_["State"] = nullptr;
                m_field_data_["PostalCode"] = nullptr;
                m_field_data_["Country"] = nullptr;
                m_field_data_["Company"] = nullptr;
                m_field_data_["Email"] = nullptr;
                m_field_data_["Phone"] = nullptr;
                m_field_data_["SSN"] = nullptr;
                m_field_data_["Username"] = nullptr;
                m_field_data_["PassportNumber"] = nullptr;
                m_field_data_["LicenseNumber"] = nullptr;
                m_field_data_["Name"] = utils::getString(name_err.value());
                m_field_data_["Notes"] = nullptr;
                m_field_data_["Fields"] = nlohmann::json::array();
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
            m_data_["identity"] = nlohmann::json::object();
            m_data_["identity"]["address1"] = nullptr;
            m_data_["identity"]["address2"] = nullptr;
            m_data_["identity"]["address3"] = nullptr;
            m_data_["identity"]["city"] = nullptr;
            m_data_["identity"]["company"] = nullptr;
            m_data_["identity"]["country"] = nullptr;
            m_data_["identity"]["email"] = nullptr;
            m_data_["identity"]["firstName"] = nullptr;
            m_data_["identity"]["lastName"] = nullptr;
            m_data_["identity"]["licenseNumber"] = nullptr;
            m_data_["identity"]["middleName"] = nullptr;
            m_data_["identity"]["passportNumber"] = nullptr;
            m_data_["identity"]["phone"] = nullptr;
            m_data_["identity"]["postalCode"] = nullptr;
            m_data_["identity"]["ssn"] = nullptr;
            m_data_["identity"]["state"] = nullptr;
            m_data_["identity"]["title"] = nullptr;
            m_data_["identity"]["username"] = nullptr;
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
            m_data_["type"] = std::to_underlying(ItemType::Identity);
            m_data_["viewPassword"] = true;

            m_init = true;
        }
    }
    
    BitwardenIdentityItem* BitwardenIdentityItem::setAddress1(
        const Botan::secure_vector<uint8_t>& address_1) {
        if (!m_init || !m_data_.contains("identity") ||
            !m_data_["identity"].is_object()) {
            return this;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->encrypt(address_1, m_item_keys);
        
        if (!value_err.has_value()) {
            return this;
        }

        std::string value = utils::getString(value_err.value());

        if (m_enable_data_field_) {
            m_field_data_["Address1"] = value;
        }

        m_data_["identity"]["address1"] = std::move(value);

        return this;
    }
    
    BitwardenIdentityItem* BitwardenIdentityItem::setAddress2(
        const Botan::secure_vector<uint8_t>& address_2) {
        if (!m_init || !m_data_.contains("identity") ||
            !m_data_["identity"].is_object()) {
            return this;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->encrypt(address_2, m_item_keys);
        
        if (!value_err.has_value()) {
            return this;
        }

        std::string value = utils::getString(value_err.value());

        if (m_enable_data_field_) {
            m_field_data_["Address2"] = value;
        }

        m_data_["identity"]["address2"] = std::move(value);

        return this;
    }
    
    BitwardenIdentityItem* BitwardenIdentityItem::setAddress3(
        const Botan::secure_vector<uint8_t>& address_3) {
        if (!m_init || !m_data_.contains("identity") ||
            !m_data_["identity"].is_object()) {
            return this;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->encrypt(address_3, m_item_keys);
        
        if (!value_err.has_value()) {
            return this;
        }

        std::string value = utils::getString(value_err.value());

        if (m_enable_data_field_) {
            m_field_data_["Address3"] = value;
        }

        m_data_["identity"]["address3"] = std::move(value);

        return this;
    }
    
    BitwardenIdentityItem* BitwardenIdentityItem::setCity(
        const Botan::secure_vector<uint8_t>& city) {
        if (!m_init || !m_data_.contains("identity") ||
            !m_data_["identity"].is_object()) {
            return this;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->encrypt(city, m_item_keys);
        
        if (!value_err.has_value()) {
            return this;
        }

        std::string value = utils::getString(value_err.value());

        if (m_enable_data_field_) {
            m_field_data_["City"] = value;
        }

        m_data_["identity"]["city"] = std::move(value);

        return this;
    }
    
    BitwardenIdentityItem* BitwardenIdentityItem::setCompany(
        const Botan::secure_vector<uint8_t>& company) {
        if (!m_init || !m_data_.contains("identity") ||
            !m_data_["identity"].is_object()) {
            return this;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->encrypt(company, m_item_keys);
        
        if (!value_err.has_value()) {
            return this;
        }

        std::string value = utils::getString(value_err.value());

        if (m_enable_data_field_) {
            m_field_data_["Company"] = value;
        }

        m_data_["identity"]["company"] = std::move(value);

        return this;
    }
    
    BitwardenIdentityItem* BitwardenIdentityItem::setCountry(
        const Botan::secure_vector<uint8_t>& country) {
        if (!m_init || !m_data_.contains("identity") ||
            !m_data_["identity"].is_object()) {
            return this;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->encrypt(country, m_item_keys);
        
        if (!value_err.has_value()) {
            return this;
        }

        std::string value = utils::getString(value_err.value());

        if (m_enable_data_field_) {
            m_field_data_["Country"] = value;
        }

        m_data_["identity"]["country"] = std::move(value);

        return this;
    }
    
    BitwardenIdentityItem* BitwardenIdentityItem::setEmail(
        const Botan::secure_vector<uint8_t>& email) {
        if (!m_init || !m_data_.contains("identity") ||
            !m_data_["identity"].is_object()) {
            return this;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->encrypt(email, m_item_keys);
        
        if (!value_err.has_value()) {
            return this;
        }

        std::string value = utils::getString(value_err.value());

        if (m_enable_data_field_) {
            m_field_data_["Email"] = value;
        }

        m_data_["identity"]["email"] = std::move(value);

        return this;
    }
    
    BitwardenIdentityItem* BitwardenIdentityItem::setFirstName(
        const Botan::secure_vector<uint8_t>& first_name) {
        if (!m_init || !m_data_.contains("identity") ||
            !m_data_["identity"].is_object()) {
            return this;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->encrypt(first_name, m_item_keys);
        
        if (!value_err.has_value()) {
            return this;
        }

        std::string value = utils::getString(value_err.value());

        if (m_enable_data_field_) {
            m_field_data_["FirstName"] = value;
        }

        m_data_["identity"]["firstName"] = std::move(value);

        return this;
    }
    
    BitwardenIdentityItem* BitwardenIdentityItem::setLastName(
        const Botan::secure_vector<uint8_t>& last_name) {
        if (!m_init || !m_data_.contains("identity") ||
            !m_data_["identity"].is_object()) {
            return this;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->encrypt(last_name, m_item_keys);
        
        if (!value_err.has_value()) {
            return this;
        }

        std::string value = utils::getString(value_err.value());

        if (m_enable_data_field_) {
            m_field_data_["LastName"] = value;
        }

        m_data_["identity"]["lastName"] = std::move(value);

        return this;
    }
    
    BitwardenIdentityItem* BitwardenIdentityItem::setLicenceNumber(
        const Botan::secure_vector<uint8_t>& license_number) {
        if (!m_init || !m_data_.contains("identity") ||
            !m_data_["identity"].is_object()) {
            return this;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->encrypt(license_number, m_item_keys);
        
        if (!value_err.has_value()) {
            return this;
        }

        std::string value = utils::getString(value_err.value());

        if (m_enable_data_field_) {
            m_field_data_["LicenseNumber"] = value;
        }

        m_data_["identity"]["licenseNumber"] = std::move(value);

        return this;
    }
    
    BitwardenIdentityItem* BitwardenIdentityItem::setMiddleName(
        const Botan::secure_vector<uint8_t>& middle_name) {
        if (!m_init || !m_data_.contains("identity") ||
            !m_data_["identity"].is_object()) {
            return this;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->encrypt(middle_name, m_item_keys);
        
        if (!value_err.has_value()) {
            return this;
        }

        std::string value = utils::getString(value_err.value());

        if (m_enable_data_field_) {
            m_field_data_["MiddleName"] = value;
        }

        m_data_["identity"]["middleName"] = std::move(value);

        return this;
    }
    
    BitwardenIdentityItem* BitwardenIdentityItem::setPassportNumber(
        const Botan::secure_vector<uint8_t>& passport_number) {
        if (!m_init || !m_data_.contains("identity") ||
            !m_data_["identity"].is_object()) {
            return this;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->encrypt(passport_number, m_item_keys);
        
        if (!value_err.has_value()) {
            return this;
        }

        std::string value = utils::getString(value_err.value());

        if (m_enable_data_field_) {
            m_field_data_["PassportNumber"] = value;
        }

        m_data_["identity"]["passportNumber"] = std::move(value);

        return this;
    }
    
    BitwardenIdentityItem* BitwardenIdentityItem::setPhone(
        const Botan::secure_vector<uint8_t>& phone) {
        if (!m_init || !m_data_.contains("identity") ||
            !m_data_["identity"].is_object()) {
            return this;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->encrypt(phone, m_item_keys);
        
        if (!value_err.has_value()) {
            return this;
        }

        std::string value = utils::getString(value_err.value());

        if (m_enable_data_field_) {
            m_field_data_["Phone"] = value;
        }

        m_data_["identity"]["phone"] = std::move(value);

        return this;
    }
    
    BitwardenIdentityItem* BitwardenIdentityItem::setPostalCode(
        const Botan::secure_vector<uint8_t>& postal_code) {
        if (!m_init || !m_data_.contains("identity") ||
            !m_data_["identity"].is_object()) {
            return this;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->encrypt(postal_code, m_item_keys);
        
        if (!value_err.has_value()) {
            return this;
        }

        std::string value = utils::getString(value_err.value());

        if (m_enable_data_field_) {
            m_field_data_["PostalCode"] = value;
        }

        m_data_["identity"]["postalCode"] = std::move(value);

        return this;
    }
    
    BitwardenIdentityItem* BitwardenIdentityItem::setSSN(
        const Botan::secure_vector<uint8_t>& ssn) {
        if (!m_init || !m_data_.contains("identity") ||
            !m_data_["identity"].is_object()) {
            return this;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->encrypt(ssn, m_item_keys);
        
        if (!value_err.has_value()) {
            return this;
        }

        std::string value = utils::getString(value_err.value());

        if (m_enable_data_field_) {
            m_field_data_["SSN"] = value;
        }

        m_data_["identity"]["ssn"] = std::move(value);

        return this;
    }
    
    BitwardenIdentityItem* BitwardenIdentityItem::setState(
        const Botan::secure_vector<uint8_t>& state) {
        if (!m_init || !m_data_.contains("identity") ||
            !m_data_["identity"].is_object()) {
            return this;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->encrypt(state, m_item_keys);
        
        if (!value_err.has_value()) {
            return this;
        }

        std::string value = utils::getString(value_err.value());

        if (m_enable_data_field_) {
            m_field_data_["State"] = value;
        }

        m_data_["identity"]["state"] = std::move(value);

        return this;
    }
    
    BitwardenIdentityItem* BitwardenIdentityItem::setTitle(
        const Botan::secure_vector<uint8_t>& title) {
        if (!m_init || !m_data_.contains("identity") ||
            !m_data_["identity"].is_object()) {
            return this;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->encrypt(title, m_item_keys);
        
        if (!value_err.has_value()) {
            return this;
        }

        std::string value = utils::getString(value_err.value());

        if (m_enable_data_field_) {
            m_field_data_["Title"] = value;
        }

        m_data_["identity"]["title"] = std::move(value);

        return this;
    }
    
    BitwardenIdentityItem* BitwardenIdentityItem::setUsername(
        const Botan::secure_vector<uint8_t>& username) {
        if (!m_init || !m_data_.contains("identity") ||
            !m_data_["identity"].is_object()) {
            return this;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->encrypt(username, m_item_keys);
        
        if (!value_err.has_value()) {
            return this;
        }

        std::string value = utils::getString(value_err.value());

        if (m_enable_data_field_) {
            m_field_data_["Username"] = value;
        }

        m_data_["identity"]["username"] = std::move(value);

        return this;
    }
    
    BitwardenIdentityItem* BitwardenIdentityItem::duplicate(ItemId& o_id) {
        std::expected<ItemKey, CryptoErrors> key_err = 
            m_vault.getOrchestrator()->getCrypto()->generateKey();
            
        if (!key_err.has_value()) {
            return this;
        }

        nlohmann::json new_data;
        nlohmann::json new_field_data;
        
        Botan::secure_vector<uint8_t> old_name;
        Botan::secure_vector<uint8_t> old_address_1;
        Botan::secure_vector<uint8_t> old_address_2;
        Botan::secure_vector<uint8_t> old_address_3;
        Botan::secure_vector<uint8_t> old_city;
        Botan::secure_vector<uint8_t> old_company;
        Botan::secure_vector<uint8_t> old_country;
        Botan::secure_vector<uint8_t> old_email;
        Botan::secure_vector<uint8_t> old_first_name;
        Botan::secure_vector<uint8_t> old_last_name;
        Botan::secure_vector<uint8_t> old_license_number;
        Botan::secure_vector<uint8_t> old_middle_name;
        Botan::secure_vector<uint8_t> old_passport_number;
        Botan::secure_vector<uint8_t> old_phone;
        Botan::secure_vector<uint8_t> old_postal_code;
        Botan::secure_vector<uint8_t> old_ssn;
        Botan::secure_vector<uint8_t> old_state;
        Botan::secure_vector<uint8_t> old_title;
        Botan::secure_vector<uint8_t> old_username;
        Botan::secure_vector<uint8_t> old_notes;
        std::vector<CustomField> old_fields;

        getName(old_name);
        getAddress1(old_address_1);
        getAddress2(old_address_2);
        getAddress3(old_address_3);
        getCity(old_city);
        getCompany(old_company);
        getCountry(old_country);
        getEmail(old_email);
        getFirstName(old_first_name);
        getLastName(old_last_name);
        getLicenceNumber(old_license_number);
        getMiddleName(old_middle_name);
        getPassportNumber(old_passport_number);
        getPhone(old_phone);
        getPostalCode(old_postal_code);
        getSSN(old_ssn);
        getState(old_state);
        getTitle(old_title);
        getUsername(old_username);
        getNotes(old_notes);
        getFields(old_fields);

        Botan::secure_vector<uint8_t> new_name;
        Botan::secure_vector<uint8_t> new_address_1;
        Botan::secure_vector<uint8_t> new_address_2;
        Botan::secure_vector<uint8_t> new_address_3;
        Botan::secure_vector<uint8_t> new_city;
        Botan::secure_vector<uint8_t> new_company;
        Botan::secure_vector<uint8_t> new_country;
        Botan::secure_vector<uint8_t> new_email;
        Botan::secure_vector<uint8_t> new_first_name;
        Botan::secure_vector<uint8_t> new_last_name;
        Botan::secure_vector<uint8_t> new_license_number;
        Botan::secure_vector<uint8_t> new_middle_name;
        Botan::secure_vector<uint8_t> new_passport_number;
        Botan::secure_vector<uint8_t> new_phone;
        Botan::secure_vector<uint8_t> new_postal_code;
        Botan::secure_vector<uint8_t> new_ssn;
        Botan::secure_vector<uint8_t> new_state;
        Botan::secure_vector<uint8_t> new_title;
        Botan::secure_vector<uint8_t> new_username;
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
         * @note Set the Address 1.
         */
        value_err = m_vault.getOrchestrator()->getCrypto()->encrypt(old_address_1, 
            key_err.value());
            
        if (!value_err.has_value()) {
            return this;
        }

        new_address_1 = std::move(value_err.value());

        /**
         * @note Set the Address 2.
         */
        value_err = m_vault.getOrchestrator()->getCrypto()->encrypt(old_address_2, 
            key_err.value());
            
        if (!value_err.has_value()) {
            return this;
        }

        new_address_2 = std::move(value_err.value());

        /**
         * @note Set the Address 3.
         */
        value_err = m_vault.getOrchestrator()->getCrypto()->encrypt(old_address_3, 
            key_err.value());
            
        if (!value_err.has_value()) {
            return this;
        }

        new_address_3 = std::move(value_err.value());

        /**
         * @note Set the City.
         */
        value_err = m_vault.getOrchestrator()->getCrypto()->encrypt(old_city, key_err.value());
            
        if (!value_err.has_value()) {
            return this;
        }

        new_city = std::move(value_err.value());

        /**
         * @note Set the Company.
         */
        value_err = m_vault.getOrchestrator()->getCrypto()->encrypt(old_company, key_err.value());
            
        if (!value_err.has_value()) {
            return this;
        }

        new_company = std::move(value_err.value());

        /**
         * @note Set the Country.
         */
        value_err = m_vault.getOrchestrator()->getCrypto()->encrypt(old_country, key_err.value());
            
        if (!value_err.has_value()) {
            return this;
        }

        new_country = std::move(value_err.value());

        /**
         * @note Set the Email.
         */
        value_err = m_vault.getOrchestrator()->getCrypto()->encrypt(old_email, key_err.value());
            
        if (!value_err.has_value()) {
            return this;
        }

        new_email = std::move(value_err.value());

        /**
         * @note Set the First Name.
         */
        value_err = m_vault.getOrchestrator()->getCrypto()->encrypt(old_first_name, 
            key_err.value());
            
        if (!value_err.has_value()) {
            return this;
        }

        new_first_name = std::move(value_err.value());

        /**
         * @note Set the Last Name.
         */
        value_err = m_vault.getOrchestrator()->getCrypto()->encrypt(old_last_name, 
            key_err.value());
            
        if (!value_err.has_value()) {
            return this;
        }

        new_last_name = std::move(value_err.value());

        /**
         * @note Set the License Number.
         */
        value_err = m_vault.getOrchestrator()->getCrypto()->encrypt(old_license_number, 
            key_err.value());
            
        if (!value_err.has_value()) {
            return this;
        }

        new_license_number = std::move(value_err.value());

        /**
         * @note Set the Middle Name.
         */
        value_err = m_vault.getOrchestrator()->getCrypto()->encrypt(old_middle_name, 
            key_err.value());
            
        if (!value_err.has_value()) {
            return this;
        }

        new_middle_name = std::move(value_err.value());

        /**
         * @note Set the Passport Number.
         */
        value_err = m_vault.getOrchestrator()->getCrypto()->encrypt(old_passport_number, 
            key_err.value());
            
        if (!value_err.has_value()) {
            return this;
        }

        new_passport_number = std::move(value_err.value());

        /**
         * @note Set the Phone.
         */
        value_err = m_vault.getOrchestrator()->getCrypto()->encrypt(old_phone, key_err.value());
            
        if (!value_err.has_value()) {
            return this;
        }

        new_phone = std::move(value_err.value());

        /**
         * @note Set the Postal Code.
         */
        value_err = m_vault.getOrchestrator()->getCrypto()->encrypt(old_postal_code, 
            key_err.value());
            
        if (!value_err.has_value()) {
            return this;
        }

        new_postal_code = std::move(value_err.value());

        /**
         * @note Set the SSN.
         */
        value_err = m_vault.getOrchestrator()->getCrypto()->encrypt(old_ssn, key_err.value());
            
        if (!value_err.has_value()) {
            return this;
        }

        new_ssn = std::move(value_err.value());

        /**
         * @note Set the State.
         */
        value_err = m_vault.getOrchestrator()->getCrypto()->encrypt(old_state, key_err.value());
            
        if (!value_err.has_value()) {
            return this;
        }

        new_state = std::move(value_err.value());

        /**
         * @note Set the Title.
         */
        value_err = m_vault.getOrchestrator()->getCrypto()->encrypt(old_title, key_err.value());
            
        if (!value_err.has_value()) {
            return this;
        }

        new_title = std::move(value_err.value());

        /**
         * @note Set the Username.
         */
        value_err = m_vault.getOrchestrator()->getCrypto()->encrypt(old_username, key_err.value());
            
        if (!value_err.has_value()) {
            return this;
        }

        new_username = std::move(value_err.value());

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
            new_field_data["Title"] = utils::getString(new_title);
            new_field_data["FirstName"] = utils::getString(new_first_name);
            new_field_data["MiddleName"] = utils::getString(new_middle_name);
            new_field_data["LastName"] = utils::getString(new_last_name);
            new_field_data["Address1"] = utils::getString(new_address_1);
            new_field_data["Address2"] = utils::getString(new_address_2);
            new_field_data["Address3"] = utils::getString(new_address_3);
            new_field_data["City"] = utils::getString(new_city);
            new_field_data["State"] = utils::getString(new_state);
            new_field_data["PostalCode"] = utils::getString(new_postal_code);
            new_field_data["Country"] = utils::getString(new_country);
            new_field_data["Company"] = utils::getString(new_company);
            new_field_data["Email"] = utils::getString(new_email);
            new_field_data["Phone"] = utils::getString(new_phone);
            new_field_data["SSN"] = utils::getString(new_ssn);
            new_field_data["Username"] = utils::getString(new_username);
            new_field_data["PassportNumber"] = utils::getString(new_passport_number);
            new_field_data["LicenseNumber"] = utils::getString(new_license_number);
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
        new_data["identity"] = nlohmann::json::object();
        new_data["identity"]["address1"] = utils::getString(new_address_1);
        new_data["identity"]["address2"] = utils::getString(new_address_2);
        new_data["identity"]["address3"] = utils::getString(new_address_3);
        new_data["identity"]["city"] = utils::getString(new_city);
        new_data["identity"]["company"] = utils::getString(new_company);
        new_data["identity"]["country"] = utils::getString(new_country);
        new_data["identity"]["email"] = utils::getString(new_email);
        new_data["identity"]["firstName"] = utils::getString(new_first_name);
        new_data["identity"]["lastName"] = utils::getString(new_last_name);
        new_data["identity"]["licenseNumber"] = utils::getString(new_license_number);
        new_data["identity"]["middleName"] = utils::getString(new_middle_name);
        new_data["identity"]["passportNumber"] = utils::getString(new_passport_number);
        new_data["identity"]["phone"] = utils::getString(new_phone);
        new_data["identity"]["postalCode"] = utils::getString(new_postal_code);
        new_data["identity"]["ssn"] = utils::getString(new_ssn);
        new_data["identity"]["state"] = utils::getString(new_state);
        new_data["identity"]["title"] = utils::getString(new_title);
        new_data["identity"]["username"] = utils::getString(new_username);
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
        new_data["type"] = std::to_underlying(ItemType::Identity);
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
        Botan::secure_scrub_memory(old_address_1.data(), old_address_1.size());
        Botan::secure_scrub_memory(old_address_2.data(), old_address_2.size());
        Botan::secure_scrub_memory(old_address_3.data(), old_address_3.size());
        Botan::secure_scrub_memory(old_city.data(), old_city.size());
        Botan::secure_scrub_memory(old_company.data(), old_company.size());
        Botan::secure_scrub_memory(old_country.data(), old_country.size());
        Botan::secure_scrub_memory(old_email.data(), old_email.size());
        Botan::secure_scrub_memory(old_first_name.data(), old_first_name.size());
        Botan::secure_scrub_memory(old_last_name.data(), old_last_name.size());
        Botan::secure_scrub_memory(old_license_number.data(), old_license_number.size());
        Botan::secure_scrub_memory(old_middle_name.data(), old_middle_name.size());
        Botan::secure_scrub_memory(old_passport_number.data(), old_passport_number.size());
        Botan::secure_scrub_memory(old_phone.data(), old_phone.size());
        Botan::secure_scrub_memory(old_postal_code.data(), old_postal_code.size());
        Botan::secure_scrub_memory(old_ssn.data(), old_ssn.size());
        Botan::secure_scrub_memory(old_state.data(), old_state.size());
        Botan::secure_scrub_memory(old_title.data(), old_title.size());
        Botan::secure_scrub_memory(old_username.data(), old_username.size());
        Botan::secure_scrub_memory(old_notes.data(), old_notes.size());
        Botan::secure_scrub_memory(new_name.data(), new_name.size());
        Botan::secure_scrub_memory(new_address_1.data(), new_address_1.size());
        Botan::secure_scrub_memory(new_address_2.data(), new_address_2.size());
        Botan::secure_scrub_memory(new_address_3.data(), new_address_3.size());
        Botan::secure_scrub_memory(new_city.data(), new_city.size());
        Botan::secure_scrub_memory(new_company.data(), new_company.size());
        Botan::secure_scrub_memory(new_country.data(), new_country.size());
        Botan::secure_scrub_memory(new_email.data(), new_email.size());
        Botan::secure_scrub_memory(new_first_name.data(), new_first_name.size());
        Botan::secure_scrub_memory(new_last_name.data(), new_last_name.size());
        Botan::secure_scrub_memory(new_license_number.data(), new_license_number.size());
        Botan::secure_scrub_memory(new_middle_name.data(), new_middle_name.size());
        Botan::secure_scrub_memory(new_passport_number.data(), new_passport_number.size());
        Botan::secure_scrub_memory(new_phone.data(), new_phone.size());
        Botan::secure_scrub_memory(new_postal_code.data(), new_postal_code.size());
        Botan::secure_scrub_memory(new_ssn.data(), new_ssn.size());
        Botan::secure_scrub_memory(new_state.data(), new_state.size());
        Botan::secure_scrub_memory(new_title.data(), new_title.size());
        Botan::secure_scrub_memory(new_username.data(), new_username.size());
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
    
    BitwardenIdentityItem* BitwardenIdentityItem::getAddress1(
        Botan::secure_vector<uint8_t>& address_1) {
        if (!m_init || !m_data_.contains("identity") ||
            !m_data_["identity"].is_object() || !m_data_["identity"].contains("address1") ||
            !m_data_["identity"]["address1"].is_string()) {
            address_1.clear();
            return this;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->decrypt(m_data_["identity"]["address1"], 
                m_item_keys);
        
        if (!value_err.has_value()) {
            return this;
        }

        address_1 = std::move(value_err.value());

        return this;
    }
    
    BitwardenIdentityItem* BitwardenIdentityItem::getAddress2(
        Botan::secure_vector<uint8_t>& address_2) {
        if (!m_init || !m_data_.contains("identity") ||
            !m_data_["identity"].is_object() || !m_data_["identity"].contains("address2") ||
            !m_data_["identity"]["address2"].is_string()) {
            address_2.clear();
            return this;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->decrypt(m_data_["identity"]["address2"], 
                m_item_keys);
        
        if (!value_err.has_value()) {
            return this;
        }

        address_2 = std::move(value_err.value());

        return this;
    }
    
    BitwardenIdentityItem* BitwardenIdentityItem::getAddress3(
        Botan::secure_vector<uint8_t>& address_3) {
        if (!m_init || !m_data_.contains("identity") ||
            !m_data_["identity"].is_object() || !m_data_["identity"].contains("address3") ||
            !m_data_["identity"]["address3"].is_string()) {
            address_3.clear();
            return this;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->decrypt(m_data_["identity"]["address3"], 
                m_item_keys);
        
        if (!value_err.has_value()) {
            return this;
        }

        address_3 = std::move(value_err.value());

        return this;
    }
    
    BitwardenIdentityItem* BitwardenIdentityItem::getCity(Botan::secure_vector<uint8_t>& city) {
        if (!m_init || !m_data_.contains("identity") ||
            !m_data_["identity"].is_object() || !m_data_["identity"].contains("city") ||
            !m_data_["identity"]["city"].is_string()) {
            city.clear();
            return this;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->decrypt(m_data_["identity"]["city"], 
                m_item_keys);
        
        if (!value_err.has_value()) {
            return this;
        }

        city = std::move(value_err.value());

        return this;
    }
    
    BitwardenIdentityItem* BitwardenIdentityItem::getCompany(
        Botan::secure_vector<uint8_t>& company) {
        if (!m_init || !m_data_.contains("identity") ||
            !m_data_["identity"].is_object() || !m_data_["identity"].contains("company") ||
            !m_data_["identity"]["company"].is_string()) {
            company.clear();
            return this;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->decrypt(m_data_["identity"]["company"], 
                m_item_keys);
        
        if (!value_err.has_value()) {
            return this;
        }

        company = std::move(value_err.value());

        return this;
    }
    
    BitwardenIdentityItem* BitwardenIdentityItem::getCountry(
        Botan::secure_vector<uint8_t>& country) {
        if (!m_init || !m_data_.contains("identity") ||
            !m_data_["identity"].is_object() || !m_data_["identity"].contains("country") ||
            !m_data_["identity"]["country"].is_string()) {
            country.clear();
            return this;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->decrypt(m_data_["identity"]["country"], 
                m_item_keys);
        
        if (!value_err.has_value()) {
            return this;
        }

        country = std::move(value_err.value());

        return this;
    }
    
    BitwardenIdentityItem* BitwardenIdentityItem::getEmail(
        Botan::secure_vector<uint8_t>& email) {
        if (!m_init || !m_data_.contains("identity") ||
            !m_data_["identity"].is_object() || !m_data_["identity"].contains("email") ||
            !m_data_["identity"]["email"].is_string()) {
            email.clear();
            return this;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->decrypt(m_data_["identity"]["email"], 
                m_item_keys);
        
        if (!value_err.has_value()) {
            return this;
        }

        email = std::move(value_err.value());

        return this;
    }
    
    BitwardenIdentityItem* BitwardenIdentityItem::getFirstName(
        Botan::secure_vector<uint8_t>& first_name) {
        if (!m_init || !m_data_.contains("identity") ||
            !m_data_["identity"].is_object() || !m_data_["identity"].contains("firstName") ||
            !m_data_["identity"]["firstName"].is_string()) {
            first_name.clear();
            return this;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->decrypt(m_data_["identity"]["firstName"], 
                m_item_keys);
        
        if (!value_err.has_value()) {
            return this;
        }

        first_name = std::move(value_err.value());

        return this;
    }
    
    BitwardenIdentityItem* BitwardenIdentityItem::getLastName(
        Botan::secure_vector<uint8_t>& last_name) {
        if (!m_init || !m_data_.contains("identity") ||
            !m_data_["identity"].is_object() || !m_data_["identity"].contains("lastName") ||
            !m_data_["identity"]["lastName"].is_string()) {
            last_name.clear();
            return this;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->decrypt(m_data_["identity"]["lastName"], 
                m_item_keys);
        
        if (!value_err.has_value()) {
            return this;
        }

        last_name = std::move(value_err.value());

        return this;
    }
    
    BitwardenIdentityItem* BitwardenIdentityItem::getLicenceNumber(
        Botan::secure_vector<uint8_t>& license_number) {
        if (!m_init || !m_data_.contains("identity") ||
            !m_data_["identity"].is_object() || !m_data_["identity"].contains("licenseNumber") ||
            !m_data_["identity"]["licenseNumber"].is_string()) {
            license_number.clear();
            return this;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->decrypt(m_data_["identity"]["licenseNumber"], 
                m_item_keys);
        
        if (!value_err.has_value()) {
            return this;
        }

        license_number = std::move(value_err.value());

        return this;
    }
    
    BitwardenIdentityItem* BitwardenIdentityItem::getMiddleName(
        Botan::secure_vector<uint8_t>& middle_name) {
        if (!m_init || !m_data_.contains("identity") ||
            !m_data_["identity"].is_object() || !m_data_["identity"].contains("middleName") ||
            !m_data_["identity"]["middleName"].is_string()) {
            middle_name.clear();
            return this;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->decrypt(m_data_["identity"]["middleName"], 
                m_item_keys);
        
        if (!value_err.has_value()) {
            return this;
        }

        middle_name = std::move(value_err.value());

        return this;
    }
    
    BitwardenIdentityItem* BitwardenIdentityItem::getPassportNumber(
        Botan::secure_vector<uint8_t>& passport_number) {
        if (!m_init || !m_data_.contains("identity") ||
            !m_data_["identity"].is_object() || !m_data_["identity"].contains("passportNumber") ||
            !m_data_["identity"]["passportNumber"].is_string()) {
            passport_number.clear();
            return this;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->decrypt(m_data_["identity"]["passportNumber"], 
                m_item_keys);
        
        if (!value_err.has_value()) {
            return this;
        }

        passport_number = std::move(value_err.value());

        return this;
    }
    
    BitwardenIdentityItem* BitwardenIdentityItem::getPhone(
        Botan::secure_vector<uint8_t>& phone) {
        if (!m_init || !m_data_.contains("identity") ||
            !m_data_["identity"].is_object() || !m_data_["identity"].contains("phone") ||
            !m_data_["identity"]["phone"].is_string()) {
            phone.clear();
            return this;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->decrypt(m_data_["identity"]["phone"], 
                m_item_keys);
        
        if (!value_err.has_value()) {
            return this;
        }

        phone = std::move(value_err.value());

        return this;
    }
    
    BitwardenIdentityItem* BitwardenIdentityItem::getPostalCode(
        Botan::secure_vector<uint8_t>& postal_code) {
        if (!m_init || !m_data_.contains("identity") ||
            !m_data_["identity"].is_object() || !m_data_["identity"].contains("postalCode") ||
            !m_data_["identity"]["postalCode"].is_string()) {
            postal_code.clear();
            return this;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->decrypt(m_data_["identity"]["postalCode"], 
                m_item_keys);
        
        if (!value_err.has_value()) {
            return this;
        }

        postal_code = std::move(value_err.value());

        return this;
    }
    
    BitwardenIdentityItem* BitwardenIdentityItem::getSSN(Botan::secure_vector<uint8_t>& ssn) {
        if (!m_init || !m_data_.contains("identity") ||
            !m_data_["identity"].is_object() || !m_data_["identity"].contains("ssn") ||
            !m_data_["identity"]["ssn"].is_string()) {
            ssn.clear();
            return this;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->decrypt(m_data_["identity"]["ssn"], 
                m_item_keys);
        
        if (!value_err.has_value()) {
            return this;
        }

        ssn = std::move(value_err.value());

        return this;
    }
    
    BitwardenIdentityItem* BitwardenIdentityItem::getState(Botan::secure_vector<uint8_t>& state) {
        if (!m_init || !m_data_.contains("identity") ||
            !m_data_["identity"].is_object() || !m_data_["identity"].contains("state") ||
            !m_data_["identity"]["state"].is_string()) {
            state.clear();
            return this;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->decrypt(m_data_["identity"]["state"], 
                m_item_keys);
        
        if (!value_err.has_value()) {
            return this;
        }

        state = std::move(value_err.value());

        return this;
    }
    
    BitwardenIdentityItem* BitwardenIdentityItem::getTitle(Botan::secure_vector<uint8_t>& title) {
        if (!m_init || !m_data_.contains("identity") ||
            !m_data_["identity"].is_object() || !m_data_["identity"].contains("title") ||
            !m_data_["identity"]["title"].is_string()) {
            title.clear();
            return this;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->decrypt(m_data_["identity"]["title"], 
                m_item_keys);
        
        if (!value_err.has_value()) {
            return this;
        }

        title = std::move(value_err.value());

        return this;
    }
    
    BitwardenIdentityItem* BitwardenIdentityItem::getUsername(
        Botan::secure_vector<uint8_t>& username) {
        if (!m_init || !m_data_.contains("identity") ||
            !m_data_["identity"].is_object() || !m_data_["identity"].contains("username") ||
            !m_data_["identity"]["username"].is_string()) {
            username.clear();
            return this;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->decrypt(m_data_["identity"]["username"], 
                m_item_keys);
        
        if (!value_err.has_value()) {
            return this;
        }

        username = std::move(value_err.value());

        return this;
    }
    
    BitwardenIdentityItem* BitwardenIdentityItem::getType(ItemType& val) {
        val = ItemType::Identity;
        return this;
    }
}