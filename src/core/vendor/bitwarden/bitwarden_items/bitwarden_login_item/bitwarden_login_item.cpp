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
            if (!localVault.features.checkAbove26_8_1()) {
                m_data_["bankAccount"] = nullptr;
                m_data_["driversLicense"] = nullptr;
                m_data_["passport"] = nullptr;
            }
            m_data_["revisionDate"] = nullptr;
            m_data_["secureNote"] = nullptr;
            m_data_["sshKey"] = nullptr;
            m_data_["type"] = 1;
            m_data_["viewPassword"] = true;
        }
    }
    
    BitwardenLoginItem* setUsername(std::string& username) {
        
    }
    
    BitwardenLoginItem* setPassword(std::string& password) {
        
    }
    
    BitwardenLoginItem* setTotp(std::string& totp) {
        
    }
    
    BitwardenLoginItem* addWebsite(std::string& website) {
        
    }
    
    BitwardenLoginItem* removeWebsite(std::string& website) {
        
    }
    
    BitwardenLoginItem* duplicate(std::string& id) {
        
    }
    
    BitwardenLoginItem* getUsername(std::string& username) {
        
    }
    
    BitwardenLoginItem* getPassword(std::string& password) {
        
    }
    
    BitwardenLoginItem* getTotp(TOTPCode& totp) {
        
    }
    
    BitwardenLoginItem* getTotpSecret(std::string& totp) {
        
    }
    
    BitwardenLoginItem* getWebsites(std::vector<std::string>& website) {
        
    }
    
    BitwardenLoginItem* getPasswordHistory(std::vector<std::pair<std::time_t, std::string>>& value) {
        
    }
    
    BitwardenLoginItem* getPasskeyCreationDate(std::vector<std::time_t>& value) {
        
    }
    
    BitwardenLoginItem* getType(CipherType& val) {
        
    }
}