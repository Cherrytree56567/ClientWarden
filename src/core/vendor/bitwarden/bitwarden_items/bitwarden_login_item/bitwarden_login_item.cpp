#include "bitwarden_login_item.h"

namespace clientwarden::vendor::bitwarden {
    BitwardenLoginItem::BitwardenLoginItem(Vault& vault, ItemId id, bool item_creation)
     : GenericItemImpl<BitwardenGenericItem, BitwardenLoginItem>(vault, id, item_creation) {
        if (!item_creation) {
            if (!m_data_.contains("login") || !m_data_["login"].is_object() ||
                !m_data_.contains("type") || !m_data_["type"].is_number_integer() ||
                m_data_["type"] != std::to_underlying(ItemType::Login)) {
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
            m_data_["type"] = std::to_underlying(ItemType::Login);
            m_data_["viewPassword"] = true;

            m_init = true;
        }
    }
    
    BitwardenLoginItem* BitwardenLoginItem::setUsername(Botan::secure_vector<uint8_t>& username) {
        if (!m_init || !m_data_.contains("login") ||
            !m_data_["login"].is_object()) {
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

        m_data_["login"]["username"] = std::move(value);

        return this;
    }
    
    BitwardenLoginItem* BitwardenLoginItem::setPassword(Botan::secure_vector<uint8_t>& password) {
        if (!m_init || !m_data_.contains("login") ||
            !m_data_["login"].is_object()) {
            return this;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->encrypt(password, m_item_keys);
        
        if (!value_err.has_value()) {
            return this;
        }

        std::string value = utils::getString(value_err.value());

        if (m_enable_data_field_) {
            m_field_data_["Password"] = value;
        }

        m_data_["login"]["password"] = std::move(value);

        return this;
    }
    
    BitwardenLoginItem* BitwardenLoginItem::setTotp(Botan::secure_vector<uint8_t>& totp) {
        if (!m_init || !m_data_.contains("login") ||
            !m_data_["login"].is_object()) {
            return this;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->encrypt(totp, m_item_keys);
        
        if (!value_err.has_value()) {
            return this;
        }

        std::string value = utils::getString(value_err.value());

        if (m_enable_data_field_) {
            m_field_data_["Totp"] = value;
        }

        m_data_["login"]["totp"] = std::move(value);

        return this;
    }
    
    BitwardenLoginItem* BitwardenLoginItem::addWebsite(Botan::secure_vector<uint8_t>& website) {
        if (!m_init || !m_data_.contains("login") ||
            !m_data_["login"].is_object()) {
            return this;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->encrypt(website, m_item_keys);
        
        if (!value_err.has_value()) {
            return this;
        }

        std::string value = utils::getString(value_err.value());

        if (!m_data_["login"].contains("uris") || !m_data_["login"]["uris"].is_array() ||
            m_data_["login"]["uris"].empty()) {
            m_data_["login"]["uris"] = nlohmann::json::array();
            m_data_["login"]["uri"] = value;
        }

        if (m_enable_data_field_) {
            m_field_data_["Uris"].push_back(value);
        }

        m_data_["login"]["uris"].push_back(std::move(value));

        return this;
    }
    
    BitwardenLoginItem* BitwardenLoginItem::removeWebsite(Botan::secure_vector<uint8_t>& website) {
        if (!m_init || !m_data_.contains("login") ||
            !m_data_["login"].is_object()) {
            return this;
        }

        if (!m_data_["login"].contains("uris") || !m_data_["login"]["uris"].is_array()) {
            return this;
        }

        if (m_enable_data_field_) {
            std::erase_if(m_field_data_["Uris"], [&](nlohmann::json uri) {
                if (!uri.is_string()) {
                    return false;
                }

                std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
                    m_vault.getOrchestrator()->getCrypto()->decrypt(uri.get<std::string>(), 
                    m_item_keys);
                
                if (!value_err.has_value()) {
                    return false;
                }
                
                return value_err.value() == website;
            });
        }

        std::erase_if(m_data_["login"]["uris"], [&](nlohmann::json uri) {
            if (!uri.is_string()) {
                return false;
            }

            std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
                m_vault.getOrchestrator()->getCrypto()->decrypt(uri.get<std::string>(), 
                m_item_keys);
            
            if (!value_err.has_value()) {
                return false;
            }
            
            return value_err.value() == website;
        });

        return this;
    }
    
    BitwardenLoginItem* BitwardenLoginItem::duplicate(ItemId& o_id) {
        std::expected<ItemKey, CryptoErrors> key_err = 
            m_vault.getOrchestrator()->getCrypto()->generateKey();
            
        if (!key_err.has_value()) {
            return this;
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
        getPassword(old_password);
        getTotpSecret(old_totp);
        getNotes(old_notes);
        getWebsites(old_websites);
        getPasswordHistory(old_password_history);
        getFields(old_fields);

        Botan::secure_vector<uint8_t> new_name;
        Botan::secure_vector<uint8_t> new_username;
        Botan::secure_vector<uint8_t> new_password;
        Botan::secure_vector<uint8_t> new_totp;
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
         * @note Set the Username.
         */
        value_err = m_vault.getOrchestrator()->getCrypto()->encrypt(old_username, key_err.value());
            
        if (!value_err.has_value()) {
            return this;
        }

        new_username = std::move(value_err.value());

        /**
         * @note Set the Password.
         */
        value_err = m_vault.getOrchestrator()->getCrypto()->encrypt(old_password, key_err.value());
            
        if (!value_err.has_value()) {
            return this;
        }

        new_password = std::move(value_err.value());

        /**
         * @note Set the TOTP.
         */
        value_err = m_vault.getOrchestrator()->getCrypto()->encrypt(old_totp, key_err.value());
            
        if (!value_err.has_value()) {
            return this;
        }

        new_totp = std::move(value_err.value());

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
        new_data["login"]["uri"] = nullptr;
        new_data["login"]["uris"] = nlohmann::json::array();
        new_data["login"]["username"] = utils::getString(new_username);
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
        new_data["type"] = std::to_underlying(ItemType::Login);
        new_data["viewPassword"] = m_data_["viewPassword"];

        /**
         * @note Set the Websites
         */
        bool first = true;
        for (Botan::secure_vector<uint8_t>& website : old_websites) {
            value_err = m_vault.getOrchestrator()->getCrypto()->encrypt(website, key_err.value());
            
            if (!value_err.has_value()) {
                continue;
            }

            if (first) {
                new_data["login"]["uri"] = utils::getString(value_err.value());
                first = false;
            }

            if (m_enable_data_field_) {
                new_field_data["Uris"].push_back(utils::getString(value_err.value()));
            }

            new_data["login"]["uris"].push_back(utils::getString(std::move(value_err.value())));

            Botan::secure_scrub_memory(website.data(), website.size());
        }

        /**
         * @note Set the Password History.
         */
        for (PasswordHistory& history : old_password_history) {
            value_err = m_vault.getOrchestrator()->getCrypto()->encrypt(history.password, 
                key_err.value());
            
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

            new_data["passwordHistory"].push_back(std::move(data_field_history));

            Botan::secure_scrub_memory(history.password.data(), history.password.size());
        }

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
        Botan::secure_scrub_memory(old_username.data(), old_username.size());
        Botan::secure_scrub_memory(old_password.data(), old_password.size());
        Botan::secure_scrub_memory(old_totp.data(), old_totp.size());
        Botan::secure_scrub_memory(old_notes.data(), old_notes.size());
        Botan::secure_scrub_memory(new_name.data(), new_name.size());
        Botan::secure_scrub_memory(new_username.data(), new_username.size());
        Botan::secure_scrub_memory(new_password.data(), new_password.size());
        Botan::secure_scrub_memory(new_totp.data(), new_totp.size());
        Botan::secure_scrub_memory(new_notes.data(), new_notes.size());
        
        key_err.value().clear();

        if (m_enable_data_field_) {
            new_data["data"] = new_field_data.dump();
        }

        OrchestratorError action_err = 
            m_vault.getOrchestrator()->newItem(new_data);
            
        o_id = new_data["id"];

        return this;
    }
    
    BitwardenLoginItem* BitwardenLoginItem::getUsername(Botan::secure_vector<uint8_t>& username) {
        if (!m_init || !m_data_.contains("login") ||
            !m_data_["login"].is_object() || !m_data_["login"].contains("username") ||
            !m_data_["login"]["username"].is_string()) {
            return this;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->decrypt(m_data_["login"]["username"], m_item_keys);
        
        if (!value_err.has_value()) {
            return this;
        }

        username = std::move(value_err.value());

        return this;
    }
    
    BitwardenLoginItem* BitwardenLoginItem::getPassword(Botan::secure_vector<uint8_t>& password) {
        if (!m_init || !m_data_.contains("login") ||
            !m_data_["login"].is_object() || !m_data_["login"].contains("password") ||
            !m_data_["login"]["password"].is_string()) {
            return this;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->decrypt(m_data_["login"]["password"], m_item_keys);
        
        if (!value_err.has_value()) {
            return this;
        }

        password = std::move(value_err.value());

        return this;
    }
    
    BitwardenLoginItem* BitwardenLoginItem::getTotp(TOTPCode& totp) {
        if (!m_init || !m_data_.contains("login") ||
            !m_data_["login"].is_object() || !m_data_["login"].contains("totp") ||
            !m_data_["login"]["totp"].is_string()) {
            return this;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->decrypt(m_data_["login"]["totp"], m_item_keys);
        
        if (!value_err.has_value()) {
            return this;
        }

        Botan::secure_vector<uint8_t> raw_val = std::move(value_err.value());

        Botan::secure_vector<uint8_t> secret;
        std::string algo = "SHA-1";
        int digits = 6;
        int period = 30;

        std::string_view raw(reinterpret_cast<const char*>(
            raw_val.data()), raw_val.size());
        
        if (raw.starts_with("otpauth://")) {
            /**
             * @brief First, parse the URL, then get all the values and then use botan to generate a
             *  totp code.
             */
            boost::urls::result<boost::urls::url_view> url_result = 
                boost::urls::parse_uri({reinterpret_cast<const char*>(
                    raw_val.data()), raw_val.size()});
            if (!url_result) {
                return this;
            }

            boost::urls::url_view parsed_url = url_result.value();

            if (parsed_url.scheme() != "otpauth" || parsed_url.encoded_host() != "totp") {
                return this;
            }

            for (boost::urls::param_pct_view param : parsed_url.encoded_params()) {
                if (std::string_view(param.key) == "secret") {
                    std::string_view val(param.value);
                    secret.assign(val.begin(), val.end());
                } else if (std::string_view(param.key) == "algorithm") {
                    algo = std::string(std::string_view(param.value));
                } else if (std::string_view(param.key) == "digits") {
                    digits = utils::getInt(std::string(std::string_view(param.value)), 6);
                } else if (std::string_view(param.key) == "period") {
                    period = utils::getInt(std::string(std::string_view(param.value)), 30);
                }
            }

            if (secret.empty()) {
                return this;
            }
        } else {
            secret = raw_val;
        }

        Botan::secure_vector<uint8_t> secure_secret = utils::b32Decode(secret);

        Botan::secure_scrub_memory(raw_val.data(), raw_val.size());
        Botan::secure_scrub_memory(secret.data(), secret.size());

        if (algo == "sha256" || algo == "SHA256") {
            algo = "SHA-256";
        } else if (algo == "sha512" || algo == "SHA512") {
            algo = "SHA-512";
        } else {
            algo = "SHA-1";
        }

        if (digits > 8 || digits < 6) {
            digits = 6;
        }

        if (period < 1 || period > 3600) {
            period = 30;
        }

        Botan::TOTP totp_code(secure_secret.data(), secure_secret.size(), algo, digits, period);

        Botan::secure_scrub_memory(secure_secret.data(), secure_secret.size());

        uint32_t code = totp_code.generate_totp(std::chrono::system_clock::now());

        /**
         * @note Get Secure Vector should pad the int
         */
        totp.code = utils::getSecureVector(code);
        totp.remaining = utils::s_getTime(utils::s_getCurrentTime(period));
        totp.period = period;

        return this;
    }
    
    BitwardenLoginItem* BitwardenLoginItem::getTotpSecret(Botan::secure_vector<uint8_t>& totp) {
        if (!m_init || !m_data_.contains("login") ||
            !m_data_["login"].is_object() || !m_data_["login"].contains("totp") ||
            !m_data_["login"]["totp"].is_string()) {
            return this;
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
            m_vault.getOrchestrator()->getCrypto()->decrypt(m_data_["login"]["totp"], m_item_keys);
        
        if (!value_err.has_value()) {
            return this;
        }

        totp = std::move(value_err.value());

        return this;
    }
    
    BitwardenLoginItem* BitwardenLoginItem::getWebsites(std::vector<Botan::secure_vector<uint8_t>>& websites) {
        if (!m_init || !m_data_.contains("login") ||
            !m_data_["login"].is_object() || !m_data_["login"].contains("uris") ||
            !m_data_["login"]["uris"].is_array()) {
            return this;
        }

        for (nlohmann::json uri : m_data_["login"]["uris"]) {
            std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> value_err = 
                m_vault.getOrchestrator()->getCrypto()->decrypt(uri, m_item_keys);
            
            if (!value_err.has_value()) {
                continue;
            }

            websites.push_back(std::move(value_err.value()));
        }

        return this;
    }
    
    BitwardenLoginItem* BitwardenLoginItem::getPasswordHistory(std::vector<PasswordHistory>& value) {
        if (!m_init || !m_data_.contains("passwordHistory") ||
            !m_data_["passwordHistory"].is_array()) {
            return this;
        }

        for (nlohmann::json history : m_data_["passwordHistory"]) {
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

            value.push_back(std::move(hist));
        }

        return this;
    }
    
    BitwardenLoginItem* BitwardenLoginItem::getPasskeyCreationDate(std::vector<Timestamp>& value) {
        if (!m_init || !m_data_.contains("login") ||
            !m_data_["login"].is_object() || !m_data_["login"].contains("fido2Credentials") ||
            !m_data_["login"]["fido2Credentials"].is_array()) {
            return this;
        }

        for (nlohmann::json passkey : m_data_["login"]["fido2Credentials"]) {
            if (!passkey.contains("creationDate") || !passkey["creationDate"].is_string()) {
                continue;
            }

            value.push_back(utils::s_getTime(passkey["creationDate"]));
        }

        return this;
    }
    
    BitwardenLoginItem* BitwardenLoginItem::getType(ItemType& val) {
        val = ItemType::Login;
        return this;
    }
}