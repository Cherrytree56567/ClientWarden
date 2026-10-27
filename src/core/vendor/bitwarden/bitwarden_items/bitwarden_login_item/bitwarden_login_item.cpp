#include "bitwarden_login_item.h"

namespace clientwarden::vendor::bitwarden {
    BitwardenLoginItem(Vault& vault, ItemId id, bool item_creation)
     : GenericItemImpl<BitwardenGenericItem, BitwardenLoginItem>(vault, id, item_creation) {
        if (!item_creation) {
            if (!m_data_.contains("login") || !m_data_["login"].is_object() ||
                !m_data_.contains("type") || !m_data_["type"].is_number_integer() ||
                m_data["type"] != 1) {
                m_init = false;
            } else {
                m_init = true;
            }
        } else {
            m_init = false;

            std::expected<ItemKey, CryptoErrors> key_err = 
                m_vault.getOrchesstrator()->getCrypto()->generateKey();
            
            if (!key_err.has_value()) {
                return;
            }

            m_item_keys = std::move(key_err.value());

            std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> unres_key_err = 
                m_vault.getOrchesstrator()->getCrypto()->generateUnresolvedKey(key_err.value());
            
            if (!unres_key_err.has_value()) {
                return;
            }

            std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> name_err = 
                m_vault.getOrchesstrator()->getCrypto()->encrypt(utils::getSecureVector(""), 
                    m_item_keys);
            
            if (!name_err.has_value()) {
                return;
            }

            if (m_enable_data_field_) {
                m_field_data_["Fields"] = nlohmann::json::array();
                m_field_data_["Name"] = name_err.value();
                m_field_data_["Notes"] = nullptr;
                m_field_data_["Password"] = nullptr;
                m_field_data_["PasswordHistory"] = nullptr;
                m_field_data_["PasswordRevisionDate"] = nullptr;
                m_field_data_["Uris"] = nlohmann::json::array();
                m_field_data_["Username"] = nullptr;
                m_field_data_["Totp"] = nullptr;
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
            m_data_["login"] = nlohmann::json::object();
            m_data_["login"]["autofillOnPageLoad"] = nullptr;
            m_data_["login"]["fido2Credentials"] = nullptr;
            m_data_["login"]["password"] = nullptr;
            m_data_["login"]["passwordRevisionDate"] = nullptr;
            m_data_["login"]["totp"] = nullptr;
            m_data_["login"]["uri"] = nullptr;
            m_data_["login"]["uris"] = nlohmann::json::array();
            m_data_["login"]["username"] = nullptr;
            m_data_["name"] = std::move(name_err.value());
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
            m_data_["type"] = 1;
            m_data_["viewPassword"] = true;

            m_init = true;
        }
    }
    
    BitwardenLoginItem* setUsername(Botan::secure_vector<uint8_t>& username) {
        if (!m_init || !m_data_.contains("login") ||
            !m_data_["login"].is_object()) {
            return;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->encrypt(username, m_item_keys);
        
        if (!value_err.has_value()) {
            return;
        }

        std::string value = utils::getString(value_err.value());

        if (m_enable_data_field_) {
            m_field_data_["Username"] = value;
        }

        m_data_["username"] = std::move(value);
    }
    
    BitwardenLoginItem* setPassword(Botan::secure_vector<uint8_t>& password) {
        if (!m_init || !m_data_.contains("login") ||
            !m_data_["login"].is_object()) {
            return;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->encrypt(password, m_item_keys);
        
        if (!value_err.has_value()) {
            return;
        }

        std::string value = utils::getString(value_err.value());

        if (m_enable_data_field_) {
            m_field_data_["Password"] = value;
        }

        m_data_["password"] = std::move(value);
    }
    
    BitwardenLoginItem* setTotp(Botan::secure_vector<uint8_t>& totp) {
        if (!m_init || !m_data_.contains("login") ||
            !m_data_["login"].is_object()) {
            return;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->encrypt(totp, m_item_keys);
        
        if (!value_err.has_value()) {
            return;
        }

        std::string value = utils::getString(value_err.value());

        if (m_enable_data_field_) {
            m_field_data_["Totp"] = value;
        }

        m_data_["totp"] = std::move(value);
    }
    
    BitwardenLoginItem* addWebsite(Botan::secure_vector<uint8_t>& website) {
        if (!m_init || !m_data_.contains("login") ||
            !m_data_["login"].is_object()) {
            return;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->encrypt(totp, m_item_keys);
        
        if (!value_err.has_value()) {
            return;
        }

        std::string value = utils::getString(value_err.value());

        if (!m_data_["login"].contains("uris") || !m_data["login"]["uris"].is_array() ||
            m_data_["login"]["uris"].empty()) {
            m_data["login"]["uris"] = nlohmann::json::array();
            m_data["login"]["uri"] = value;
        }

        if (m_enable_data_field_) {
            m_field_data_["Uris"].push_back(value);
        }

        m_data["login"]["uris"].push_back(std::move(value));
    }
    
    BitwardenLoginItem* removeWebsite(Botan::secure_vector<uint8_t>& website) {
        if (!m_init || !m_data_.contains("login") ||
            !m_data_["login"].is_object()) {
            return;
        }

        if (!m_data_["login"].contains("uris") || !m_data["login"]["uris"].is_array()) {
            return;
        }

        if (m_enable_data_field_) {
            std::erase_if(m_field_data_["Uris"], [&](nlohmann::json uri) {
                if (!uri.is_string()) {
                    return false;
                }
                
                return uri == website;
            });
        }

        std::erase_if(m_data["login"]["uris"], [&](nlohmann::json uri) {
            if (!uri.is_string()) {
                return false;
            }
            
            return uri == website;
        });
    }
    
    BitwardenLoginItem* duplicate(ItemId& o_id) {
        std::expected<ItemKey, CryptoErrors> key_err = 
            m_vault.getOrchesstrator()->getCrypto()->generateKey();
            
        if (!key_err.has_value()) {
            return;
        }

        nlohmann::json new_data;
        nlohmann::json new_field_data;
        
        Botan::secure_vector<uint8_t> old_name;
        Botan::secure_vector<uint8_t> old_username;
        Botan::secure_vector<uint8_t> old_password;
        Botan::secure_vector<uint8_t> old_totp;
        Botan::secure_vector<uint8_t> old_notes;
        std::vector<Botan::secure_vector<uint8_t>> old_websites;
        std::vector<PasswordHistory> old_password_history;
        std::vector<CustomField> old_fields;

        getName(old_name);
        getUsername(old_username);
        getPassword(old_username);
        getTotpSecret(old_username);
        getNotes(old_username);
        getWebsites(old_websites);
        getPasswordHistory(old_password_history);
        getFields(old_fields);

        Botan::secure_vector<uint8_t> new_name;
        Botan::secure_vector<uint8_t> new_username;
        Botan::secure_vector<uint8_t> new_password;
        Botan::secure_vector<uint8_t> new_totp;
        Botan::secure_vector<uint8_t> new_notes;

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> unres_key_err = 
            m_vault.getOrchesstrator()->getCrypto()->generateUnresolvedKey(key_err.value());
            
        if (!unres_key_err.has_value()) {
            return;
        }

        /**
         * @note Set the Name.
         */
        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchesstrator()->getCrypto()->encrypt(old_name, m_item_keys);
            
        if (!value_err.has_value()) {
            return;
        }

        new_name = std::move(value_err.value());

        /**
         * @note Set the Username.
         */
        value_err = m_vault.getOrchesstrator()->getCrypto()->encrypt(old_username, m_item_keys);
            
        if (!value_err.has_value()) {
            return;
        }

        new_username = std::move(value_err.value());

        /**
         * @note Set the Password.
         */
        value_err = m_vault.getOrchesstrator()->getCrypto()->encrypt(old_password, m_item_keys);
            
        if (!value_err.has_value()) {
            return;
        }

        new_password = std::move(value_err.value());

        /**
         * @note Set the TOTP.
         */
        value_err = m_vault.getOrchesstrator()->getCrypto()->encrypt(old_totp, m_item_keys);
            
        if (!value_err.has_value()) {
            return;
        }

        new_totp = std::move(value_err.value());

        /**
         * @note Set the Notes.
         */
        value_err = m_vault.getOrchesstrator()->getCrypto()->encrypt(old_notes, m_item_keys);
            
        if (!value_err.has_value()) {
            return;
        }

        new_notes = std::move(value_err.value());

        if (m_enable_data_field_) {
            new_field_data["Fields"] = nlohmann::json::array();
            new_field_data["Name"] = utils::getString(new_name);
            new_field_data["Notes"] = utils::getString(new_notes);
            new_field_data["Password"] = utils::getString(new_password);
            new_field_data["PasswordHistory"] = nlohmann::json::array();
            new_field_data["PasswordRevisionDate"] = m_field_data_["PasswordRevisionDate"];
            new_field_data["Uris"] = nlohmann::json::array();
            new_field_data["Username"] = utils::getString(new_username);
            new_field_data["Totp"] = utils::getString(new_totp);
        }

        new_data["archivedDate"] = m_data_["archivedDate"];
        new_data["attachments"] = nullptr;
        new_data["card"] = nullptr;
        new_data["collectionIds"] = m_data_["collectionIds"];
        new_data["creationDate"] = m_data_["creationDate"];

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
        new_data["login"] = nlohmann::json::object();
        new_data["login"]["autofillOnPageLoad"] = m_data_["login"]["autofillOnPageLoad"];
        new_data["login"]["fido2Credentials"] = nullptr;
        new_data["login"]["password"] = utils::getString(new_password);
        new_data["login"]["passwordRevisionDate"] = m_data_["login"]["passwordRevisionDate"];
        new_data["login"]["totp"] = utils::getString(new_totp);
        new_data["login"]["uri"] = !new_websites.empty() ? utils::getString(new_websites[0]) : nullptr;
        new_data["login"]["uris"] = nlohmann::json::array();
        new_data["login"]["username"] = utils::getString(new_username);
        new_data["name"] = std::move(name_err.value());
        new_data["notes"] = nullptr;
        new_data["object"] = "cipherDetails";
        new_data["organizationId"] = nullptr;
        new_data["organizationUseTotp"] = nullptr;
        new_data["passwordHistory"] = nlohmann::json::array();
        new_data["permissions"] = m_data_["permissions"];
        new_data["permissions"]["delete"] = m_data_["permissions"]["delete"];
        new_data["permissions"]["restore"] = m_data_["permissions"]["restore"];
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
        new_data["type"] = 1;
        new_data["viewPassword"] = m_data_["viewPassword"];

        /**
         * @note Set the Websites
         */
        for (Botan::secure_vector<uint8_t>& website : old_websites) {
            value_err = m_vault.getOrchesstrator()->getCrypto()->encrypt(website, m_item_keys);
            
            if (!value_err.has_value()) {
                continue;
            }

            if (m_enable_data_field_) {
                new_field_data["Uris"].push_back(value_err.value());
            }

            new_data["login"]["uris"].push_back(std::move(value_err.value()));

            Botan::zap(website);
        }

        /**
         * @note Set the Password History.
         */
        for (PasswordHistory& history : old_password_history) {
            value_err = m_vault.getOrchesstrator()->getCrypto()->encrypt(history.password, 
                m_item_keys);
            
            if (!value_err.has_value()) {
                continue;
            }
            
            if (m_enable_data_field_) {
                nlohmann::json data_field_history;
                data_field_history["LastUsedDate"] = utils::getString(history.revision_date);
                data_field_history["Password"] = utils::getString(value_err.value());

                new_field_data["PasswordHistory"].push_back(std::move(data_field_history));
            }

            nlohmann::json data_field_history;
            data_field_history["lastUsedDate"] = utils::getString(history.revision_date);
            data_field_history["password"] = utils::getString(std::move(value_err.value()));

            new_field_data["passwordHistory"].push_back(std::move(data_field_history));

            Botan::zap(history.password);
        }

        /**
         * @note Set the CustomFields.
         */
        for (CustomField& field : old_fields) {
            nlohmann::json custom_data;
            nlohmann::json custom_data_field;

            custom_data["type"] = std::to_string(std::to_undelying(field.type));
            custom_data_field["Type"] = std::to_string(std::to_undelying(field.type));

            CustomField new_field;
            new_field.type = field;

            value_err = m_vault.getOrchesstrator()->getCrypto()->encrypt(field.name, 
                m_item_keys);
            
            if (!value_err.has_value()) {
                continue;
            }

            custom_data_field["Name"] = value_err.value();
            custom_data["name"] = std::move(value_err.value());

            if (field.type == CustomFieldType::Linked) {
                custom_data_field["LinkedId"] = field.value;
                custom_data["linkedId"] = field.value;
                custom_data["value"] = nullptr;
            } else {
                value_err = m_vault.getOrchesstrator()->getCrypto()->encrypt(field.value, 
                    m_item_keys);
                
                if (!value_err.has_value()) {
                    continue;
                }

                custom_data_field["Value"] = value_err.value();
                custom_data["value"] = std::move(value_err.value());
                custom_data["linkedId"] = nullptr;
            }

            if (m_enable_data_field) {
                new_field_data["Fields"].push_back(std::move(custom_data_field));
            }

            new_data["fields"].push_back(std::move(custom_data));

            Botan::zap(field.name);
            Botan::zap(field.value);
        }

        Botan::zap(old_name);
        Botan::zap(old_username);
        Botan::zap(old_password);
        Botan::zap(old_totp);
        Botan::zap(old_notes);
        
        key_err.value().clear();

        if (m_enable_data_field_) {
            new_data["data"] = new_field_data.dump();
        }

        OrchestratorError action_err = 
            m_vault.getOrchestrator()->newItem(new_data);
            
        o_id = new_item["id"];
    }
    
    BitwardenLoginItem* getUsername(Botan::secure_vector<uint8_t>& username) {
        if (!m_init || !m_data_.contains("login") ||
            !m_data_["login"].is_object() || !m_data_["login"].contains("username") ||
            !m_data_["login"]["username"].is_string()) {
            return;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->decrypt(m_data_["login"]["username"], m_item_keys);
        
        if (!value_err.has_value()) {
            return;
        }

        username = std::move(value_err.value());
    }
    
    BitwardenLoginItem* getPassword(Botan::secure_vector<uint8_t>& password) {
        if (!m_init || !m_data_.contains("login") ||
            !m_data_["login"].is_object() || !m_data_["login"].contains("password") ||
            !m_data_["login"]["password"].is_string()) {
            return;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->decrypt(m_data_["login"]["password"], m_item_keys);
        
        if (!value_err.has_value()) {
            return;
        }

        password = std::move(value_err.value());
    }
    
    BitwardenLoginItem* getTotp(TOTPCode& totp) {
        if (!m_init || !m_data_.contains("login") ||
            !m_data_["login"].is_object() || !m_data_["login"].contains("totp") ||
            !m_data_["login"]["totp"].is_string()) {
            return;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->decrypt(m_data_["login"]["totp"], m_item_keys);
        
        if (!value_err.has_value()) {
            return;
        }
        
        /**
         * @todo TOTP Stuff!
         */
    }
    
    BitwardenLoginItem* getTotpSecret(Botan::secure_vector<uint8_t>& totp) {
        if (!m_init || !m_data_.contains("login") ||
            !m_data_["login"].is_object() || !m_data_["login"].contains("totp") ||
            !m_data_["login"]["totp"].is_string()) {
            return;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->decrypt(m_data_["login"]["totp"], m_item_keys);
        
        if (!value_err.has_value()) {
            return;
        }

        totp = std::move(value_err.value());
    }
    
    BitwardenLoginItem* getWebsites(std::vector<Botan::secure_vector<uint8_t>>& websites) {
        if (!m_init || !m_data_.contains("login") ||
            !m_data_["login"].is_object() || !m_data_["login"].contains("uris") ||
            !m_data_["login"]["uris"].is_array()) {
            return;
        }

        for (nlohmann::json uri : m_data_["login"]["uris"]) {
            std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
                m_vault.getOrchestrator()->getCrypto()->decrypt(uri, m_item_keys);
            
            if (!value_err.has_value()) {
                continue;
            }

            websites.push_back(std::move(value_err.value());
        }
    }
    
    BitwardenLoginItem* getPasswordHistory(std::vector<PasswordHistory>& value) {
        if (!m_init || !m_data_.contains("login") ||
            !m_data_["login"].is_object() || !m_data_["login"].contains("passwordHistory") ||
            !m_data_["login"]["passwordHistory"].is_array()) {
            return;
        }

        for (nlohmann::json history : m_data_["login"]["passwordHistory"]) {
            if (!history.contains("password") || !history["password"].is_string() ||
                !history.contains("lastUsedDate") || !history["lastUsedDate"].is_string()) {
                continue;
            }

            std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
                m_vault.getOrchestrator()->getCrypto()->decrypt(history["password"], m_item_keys);
            
            if (!value_err.has_value()) {
                continue;
            }

            PasswordHistory hist;
            hist.password = std::move(value_err.value());
            hist.revision_date = utils::s_getTime(history["lastUsedDate"]);

            value.push_back(std::move(hist);
        }
    }
    
    BitwardenLoginItem* getPasskeyCreationDate(std::vector<Timestamp>& value) {
        if (!m_init || !m_data_.contains("login") ||
            !m_data_["login"].is_object() || !m_data_["login"].contains("fido2Credentials") ||
            !m_data_["login"]["fido2Credentials"].is_array()) {
            return;
        }

        for (nlohmann::json passkey : m_data_["login"]["fido2Credentials"]) {
            if (!passkey.contains("creationDate") || !passkey["creationDate"].is_string()) {
                continue;
            }

            value.push_back(utils::s_getTime(passkey["creationDate"]));
        }
    }
    
    BitwardenLoginItem* getType(CipherType& val) {
        val = CipherType::Login;
    }
}