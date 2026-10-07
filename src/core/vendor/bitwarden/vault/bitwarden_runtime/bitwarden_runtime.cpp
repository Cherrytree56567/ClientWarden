#include "bitwarden_runtime.h"

namespace clientwarden::vendor::bitwarden::vault {
    BitwardenRuntime::BitwardenRuntime(Storage storage) : Runtime(storage) {
        
    }
    

    RuntimeError BitwardenRuntime::loadVault() {
        if (!m_storage.exists("vault.json")) {
            return RuntimeError::VaultNotFound;
        }

        std::string vault_data = utils::getString(m_storage.read("vault.json"));

        if (!nlohmann::json::accept(vault_data)) {
            return RuntimeError::InvalidVault;
        }

        m_vault_data_ = nlohmann::json::parse(vault_data);

        return RuntimeError::Success;
    }
    

    std::expected<nlohmann::json, RuntimeError> BitwardenRuntime::getVaultData() {
        return m_vault_data_;
    }
    

    std::expected<nlohmann::json, RuntimeError> BitwardenRuntime::getItems() {
        if (!m_vault_data_.contains("ciphers") || !m_vault_data_["ciphers"].is_array()) {
            return std::unexpected(RuntimeError::InvalidVault);
        }

        return m_vault_data_["ciphers"];
    }
    

    std::expected<std::vector<ItemId>, RuntimeError> BitwardenRuntime::getItemIds() {
        if (!m_vault_data_.contains("ciphers") || !m_vault_data_["ciphers"].is_array()) {
            return std::unexpected(RuntimeError::InvalidVault);
        }

        std::vector<ItemId> ids;

        for (nlohmann::json& cipher : m_vault_data_["ciphers"]) {
            if (!cipher.contains("id") || !cipher["id"].is_string()) {
                continue;
            }

            std::string c_id = cipher["id"];
            ids.push_back(getSecureVector(c_id)();
        }

        return ids;
    }
    

    std::expected<nlohmann::json, RuntimeError> BitwardenRuntime::getItem(ItemId uuid) {
        if (!m_vault_data_.contains("ciphers") || !m_vault_data_["ciphers"].is_array()) {
            return std::unexpected(RuntimeError::InvalidVault);
        }

        for (nlohmann::json& cipher : m_vault_data_["ciphers"]) {
            if (!cipher.contains("id") || !cipher["id"].is_string()) {
                continue;
            }

            if (cipher["id"] == uuid) {
                return cipher;
            }
        }

        return std::unexpected(RuntimeError::NotFound);
    }
    

    /**
     * @todo think of some logic for this: see old impl
     */
    RuntimeError BitwardenRuntime::updateItem(ItemId uuid, nlohmann::json item) {
        nlohmann::json::iterator ciphers_iterator = m_vault_data_.find("ciphers");

        if (ciphers_iterator == m_vault_data_.end() || !ciphers_iterator->is_array()) {
            return RuntimeError::InvalidVault;
        }

        for (nlohmann::json& cipher : *ciphers_iterator) {
            if (!cipher.contains("id") || !cipher["id"].is_string()) {
                continue;
            }

            if (cipher["id"] == uuid) {
                cipher = std::move(item);
                cipher["revisionDate"] = utils::getCurrentTime();

                return RuntimeError::Success;
            }
        }

        return RuntimeError::NotFound;
    }

    RuntimeError BitwardenRuntime::addItem(nlohmann::json item) {
        
    }
    

    RuntimeError BitwardenRuntime::removeItem(ItemId uuid) {
        
    }
    

    std::expected<std::vector<ItemId>, RuntimeError> BitwardenRuntime::getFolders() {
        
    }
    

    std::expected<nlohmann::json, RuntimeError> BitwardenRuntime::getFolder(ItemId uuid) {
        
    }
    

    RuntimeError BitwardenRuntime::updateFolder(ItemId uuid, nlohmann::json folder) {
        
    }
    

    RuntimeError BitwardenRuntime::addFolder(nlohmann::json folder) {
        
    }
    

    RuntimeError BitwardenRuntime::removeFolder(ItemId uuid) {
        
    }
    

    RuntimeError BitwardenRuntime::markOfflineDeletedItem(ItemId uuid, bool mark) {
        
    }
    

    RuntimeError BitwardenRuntime::markOfflineDeletedFolder(ItemId uuid, bool mark) {
        
    }
    

    std::expected<bool, RuntimeError> BitwardenRuntime::isMarkedItem(ItemId uuid) {
        
    }
    

    std::expected<bool, RuntimeError> BitwardenRuntime::isMarkedFolder(ItemId uuid) {
        
    }
    

    std::expected<std::vector<ItemId>, RuntimeError> BitwardenRuntime::getMarkedItems() {
        
    }
    

    std::expected<std::vector<ItemId>, RuntimeError> BitwardenRuntime::getMarkedFolders() {
        
    }
    

    std::expected<Profile, RuntimeError> BitwardenRuntime::getProfile() {
        
    }
    

    std::expected<nlohmann::json, RuntimeError> BitwardenRuntime::getVaultInfo() {
        
    }
    
        
    std::expected<Botan::secure_vector<uint8_t>, RuntimeError> BitwardenRuntime::getVersion() {
        
    }
    
    
    RuntimeError BitwardenRuntime::storeVersion(Botan::secure_vector<uint8_t> version) {
        
    }
    

    Vendor BitwardenRuntime::getVendor() {
        return Vendor::BitWarden;
    }
}