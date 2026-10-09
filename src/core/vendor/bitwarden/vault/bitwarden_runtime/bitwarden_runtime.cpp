#include "bitwarden_runtime.h"

namespace clientwarden::vendor::bitwarden::vault {
    BitwardenRuntime::BitwardenRuntime(std::shared_ptr<Storage> storage) : Runtime(storage) {
        
    }

    RuntimeError BitwardenRuntime::loadVault() {
        if (!m_storage.exists("vault.json")) {
            return RuntimeError::VaultNotFound;
        }

        std::string vault_data = utils::getString(m_storage.read("vault.json"));

        if (!nlohmann::json::accept(vault_data)) {
            return RuntimeError::InvalidVault;
        }

        std::lock_guard<std::recursive_mutex> lock(m_mutex);

        m_vault_data = nlohmann::json::parse(vault_data);

        m_init = true;

        return RuntimeError::Success;
    }

    std::expected<nlohmann::json, RuntimeError> BitwardenRuntime::getVaultData() {
        if (!m_init) {
            return std::unexpected(RuntimeError::Uninitialised);
        }

        return m_vault_data;
    }

    std::expected<nlohmann::json, RuntimeError> BitwardenRuntime::getItems() {
        if (!m_init) {
            return std::unexpected(RuntimeError::Uninitialised);
        }
        
        std::lock_guard<std::recursive_mutex> lock(m_mutex);

        if (!m_vault_data.contains("ciphers") || !m_vault_data["ciphers"].is_array()) {
            return std::unexpected(RuntimeError::InvalidVault);
        }

        return m_vault_data["ciphers"];
    }

    std::expected<std::vector<ItemId>, RuntimeError> BitwardenRuntime::getItemIds() {
        if (!m_init) {
            return std::unexpected(RuntimeError::Uninitialised);
        }
        
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        
        if (!m_vault_data.contains("ciphers") || !m_vault_data["ciphers"].is_array()) {
            return std::unexpected(RuntimeError::InvalidVault);
        }

        std::vector<ItemId> ids;

        for (nlohmann::json& cipher : m_vault_data["ciphers"]) {
            if (!cipher.contains("id") || !cipher["id"].is_string()) {
                continue;
            }

            std::string c_id = cipher["id"];
            ids.push_back(utils::getSecureVector(c_id));
        }

        return ids;
    }

    std::expected<nlohmann::json, RuntimeError> BitwardenRuntime::getItem(ItemId uuid) {
        if (!m_init) {
            return std::unexpected(RuntimeError::Uninitialised);
        }
        
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        
        if (!m_vault_data.contains("ciphers") || !m_vault_data["ciphers"].is_array()) {
            return std::unexpected(RuntimeError::InvalidVault);
        }

        for (nlohmann::json& cipher : m_vault_data["ciphers"]) {
            if (!cipher.contains("id") || !cipher["id"].is_string()) {
                continue;
            }

            if (cipher["id"] == uuid) {
                return cipher;
            }
        }

        return std::unexpected(RuntimeError::NotFound);
    }
    
    RuntimeError BitwardenRuntime::updateItem(ItemId uuid, nlohmann::json item) {
        if (!m_init) {
            return RuntimeError::Uninitialised;
        }
        
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        
        nlohmann::json::iterator ciphers_iterator = m_vault_data.find("ciphers");

        if (ciphers_iterator == m_vault_data.end() || !ciphers_iterator->is_array()) {
            return RuntimeError::InvalidVault;
        }

        for (nlohmann::json& cipher : *ciphers_iterator) {
            if (!cipher.contains("id") || !cipher["id"].is_string()) {
                continue;
            }

            /**
             * @brief update item + update revision date
             */
            if (cipher["id"] == uuid) {
                cipher = std::move(item);
                cipher["revisionDate"] = utils::getCurrentTime();

                if (!cipher.contains("id") || !cipher["id"].is_string()) {
                    cipher["id"] = uuid;
                }

                if (!m_storage.write("vault.json", m_vault_data.dump(4)).has_value()) {
                    return RuntimeError::StorageFailure;
                }

                return RuntimeError::Success;
            }
        }

        return RuntimeError::NotFound;
    }

    RuntimeError BitwardenRuntime::addItem(nlohmann::json item) {
        if (!m_init) {
            return RuntimeError::Uninitialised;
        }
        
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        
        if (!m_vault_data.contains("ciphers") || !m_vault_data["ciphers"].is_array()) {
            return RuntimeError::InvalidVault;
        }

        if (!item.contains("id") || !item["id"].is_string()) {
            return RuntimeError::InvalidVault;
        }

        for (nlohmann::json& cipher : m_vault_data["ciphers"]) {
            if (!cipher.contains("id") || !cipher["id"].is_string()) {
                continue;
            }

            if (item["id"] == cipher["id"]) {
                return RuntimeError::ExistingItem;
            }
        }
        
        m_vault_data["ciphers"].push_back(item);
        
        if (!m_storage.write("vault.json", m_vault_data.dump(4)).has_value()) {
            return RuntimeError::StorageFailure;
        }

        return RuntimeError::Success;
    }

    RuntimeError BitwardenRuntime::removeItem(ItemId uuid) {
        if (!m_init) {
            return RuntimeError::Uninitialised;
        }
        
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        
        nlohmann::json::iterator ciphers_iterator = m_vault_data.find("ciphers");

        if (ciphers_iterator == m_vault_data.end() || !ciphers_iterator->is_array()) {
            return RuntimeError::InvalidVault;
        }

        nlohmann::json::iterator iterator = std::find_if(
            ciphers_iterator->begin(), ciphers_iterator->end(),
            [&uuid](const nlohmann::json& cipher) -> bool {
                if (!cipher.contains("id") || !cipher["id"].is_string()) {
                    return false;
                }
                
                return cipher["id"] == uuid;
            });

        if (iterator == ciphers_iterator->end()) {
            return RuntimeError::NotFound;
        }

        ciphers_iterator->erase(iterator);
        
        if (!m_storage.write("vault.json", m_vault_data.dump(4)).has_value()) {
            return RuntimeError::StorageFailure;
        }

        return RuntimeError::Success;
    }

    std::expected<std::vector<ItemId>, RuntimeError> BitwardenRuntime::getFolders() {
        if (!m_init) {
            return std::unexpected(RuntimeError::Uninitialised);
        }
        
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        
        if (!m_vault_data.contains("folders") || !m_vault_data["folders"].is_array()) {
            return std::unexpected(RuntimeError::InvalidVault);
        }

        std::vector<ItemId> ids;

        for (nlohmann::json& folder : m_vault_data["folders"]) {
            if (!folder.contains("id") || !folder["id"].is_string()) {
                continue;
            }

            std::string c_id = folder["id"];
            ids.push_back(getSecureVector(c_id));
        }

        return ids;
    }

    std::expected<nlohmann::json, RuntimeError> BitwardenRuntime::getFolder(ItemId uuid) {
        if (!m_init) {
            return std::unexpected(RuntimeError::Uninitialised);
        }
        
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        
        if (!m_vault_data.contains("folders") || !m_vault_data["folders"].is_array()) {
            return std::unexpected(RuntimeError::InvalidVault);
        }

        for (nlohmann::json& folder : m_vault_data["folders"]) {
            if (!folder.contains("id") || !folder["id"].is_string()) {
                continue;
            }

            if (folder["id"] == uuid) {
                return folder;
            }
        }

        return std::unexpected(RuntimeError::NotFound);
    }

    RuntimeError BitwardenRuntime::updateFolder(ItemId uuid, nlohmann::json folder_item) {
        if (!m_init) {
            return RuntimeError::Uninitialised;
        }
        
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        
        nlohmann::json::iterator folders_iterator = m_vault_data.find("folders");

        if (folders_iterator == m_vault_data.end() || !folders_iterator->is_array()) {
            return RuntimeError::InvalidVault;
        }

        for (nlohmann::json& folder : *folders_iterator) {
            if (!folder.contains("id") || !folder["id"].is_string()) {
                continue;
            }

            /**
             * @brief update item + update refresh date
             */
            if (folder["id"] == uuid) {
                folder = std::move(folder_item);
                folder["revisionDate"] = utils::getCurrentTime();
                
                if (!m_storage.write("vault.json", m_vault_data.dump(4)).has_value()) {
                    return RuntimeError::StorageFailure;
                }

                return RuntimeError::Success;
            }
        }

        return RuntimeError::NotFound;
    }

    RuntimeError BitwardenRuntime::addFolder(nlohmann::json folder_item) {
        if (!m_init) {
            return RuntimeError::Uninitialised;
        }
        
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        
        if (!m_vault_data.contains("folders") || !m_vault_data["folders"].is_array()) {
            return RuntimeError::InvalidVault;
        }

        if (!folder_item.contains("id") || !folder_item["id"].is_string()) {
            return RuntimeError::InvalidVault;
        }

        for (nlohmann::json& folder : m_vault_data["folders"]) {
            if (!folder.contains("id") || !folder["id"].is_string()) {
                continue;
            }

            if (folder_item["id"] == folder["id"]) {
                return RuntimeError::ExistingItem;
            }
        }
        
        m_vault_data["folders"].push_back(folder_item);
        
        if (!m_storage.write("vault.json", m_vault_data.dump(4)).has_value()) {
            return RuntimeError::StorageFailure;
        }

        return RuntimeError::Success;
    }

    RuntimeError BitwardenRuntime::removeFolder(ItemId uuid) {
        if (!m_init) {
            return RuntimeError::Uninitialised;
        }
        
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        
        nlohmann::json::iterator folders_iterator = m_vault_data.find("folders");

        if (folders_iterator == m_vault_data.end() || !folders_iterator->is_array()) {
            return RuntimeError::InvalidVault;
        }

        nlohmann::json::iterator iterator = std::find_if(
            folders_iterator->begin(), folders_iterator->end(),
            [&uuid](const nlohmann::json& folder) -> bool {
                if (!folder.contains("id") || !folder["id"].is_string()) {
                    return false;
                }
                
                return folder["id"] == uuid;
            });

        if (iterator == folders_iterator->end()) {
            return RuntimeError::NotFound;
        }

        folders_iterator->erase(iterator);
        
        if (!m_storage.write("vault.json", m_vault_data.dump(4)).has_value()) {
            return RuntimeError::StorageFailure;
        }

        return RuntimeError::Success;
    }

    RuntimeError BitwardenRuntime::markOfflineDeletedItem(ItemId uuid, bool mark) {
        if (!m_init) {
            return RuntimeError::Uninitialised;
        }
        
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        
        if (!m_vault_data.contains("offlineDeleted") || !m_vault_data["offlineDeleted"].is_array()) {
            m_vault_data["offlineDeleted"] = nlohmann::json::array();
        }

        nlohmann::json& offline_items = m_vault_data["offlineDeleted"];

        if (mark && std::find(offline_items.begin(), 
                                offline_items.end(), uuid) == offline_items.end()) {
            offline_items.push_back(uuid);
        } else if (!mark) {
            nlohmann::json::iterator item_iterator = std::remove_if(
                offline_items.begin(), offline_items.end(),
                [&uuid](const nlohmann::json& element) -> bool {
                    return element.is_string() && element.get_ref<const std::string&>() == uuid;
                });

            offline_items.erase(item_iterator, offline_items.end());
        }
        
        if (!m_storage.write("vault.json", m_vault_data.dump(4)).has_value()) {
            return RuntimeError::StorageFailure;
        }

        return RuntimeError::Success;
    }

    RuntimeError BitwardenRuntime::markOfflineCreatedItem(ItemId uuid, bool mark) {
        if (!m_init) {
            return RuntimeError::Uninitialised;
        }
        
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        
        if (!m_vault_data.contains("offlineItems") || !m_vault_data["offlineItems"].is_array()) {
            m_vault_data["offlineItems"] = nlohmann::json::array();
        }

        nlohmann::json& offline_items = m_vault_data["offlineItems"];

        if (mark && std::find(offline_items.begin(), 
                                offline_items.end(), uuid) == offline_items.end()) {
            offline_items.push_back(uuid);
        } else if (!mark) {
            nlohmann::json::iterator item_iterator = std::remove_if(
                offline_items.begin(), offline_items.end(),
                [&uuid](const nlohmann::json& element) -> bool {
                    return element.is_string() && element.get_ref<const std::string&>() == uuid;
                });

            offline_items.erase(item_iterator, offline_items.end());
        }
        
        if (!m_storage.write("vault.json", m_vault_data.dump(4)).has_value()) {
            return RuntimeError::StorageFailure;
        }

        return RuntimeError::Success;
    }

    RuntimeError BitwardenRuntime::markOfflineDeletedFolder(ItemId uuid, bool mark) {
        if (!m_init) {
            return RuntimeError::Uninitialised;
        }
        
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        
        if (!m_vault_data.contains("offlineFolders") || !m_vault_data["offlineFolders"].is_array()) {
            m_vault_data["offlineFolders"] = nlohmann::json::array();
        }

        nlohmann::json& offline_folders = m_vault_data["offlineFolders"];

        if (mark && std::find(offline_folders.begin(), 
                                offline_folders.end(), uuid) == offline_folders.end()) {
            offline_folders.push_back(uuid);
        } else if (!mark) {
            nlohmann::json::iterator item_iterator = std::remove_if(
                offline_folders.begin(), offline_folders.end(),
                [&uuid](const nlohmann::json& element) -> bool {
                    return element.is_string() && element.get_ref<const std::string&>() == uuid;
                });

            offline_folders.erase(item_iterator, offline_folders.end());
        }
        
        if (!m_storage.write("vault.json", m_vault_data.dump(4)).has_value()) {
            return RuntimeError::StorageFailure;
        }

        return RuntimeError::Success;
    }

    std::expected<bool, RuntimeError> BitwardenRuntime::isMarkedItem(ItemId uuid) {
        if (!m_init) {
            return std::unexpected(RuntimeError::Uninitialised);
        }
        
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        
        if (!m_vault_data.contains("offlineItems") || !m_vault_data["offlineItems"].is_array()) {
            m_vault_data["offlineItems"] = nlohmann::json::array();
            return false;
        }

        nlohmann::json& offline_items = m_vault_data["offlineItems"];

        return std::find(offline_items.begin(), offline_items.end(), uuid) != offline_items.end();
    }

    std::expected<bool, RuntimeError> BitwardenRuntime::isMarkedFolder(ItemId uuid) {
        if (!m_init) {
            return std::unexpected(RuntimeError::Uninitialised);
        }
        
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        
        if (!m_vault_data.contains("offlineFolders") || !m_vault_data["offlineFolders"].is_array()) {
            m_vault_data["offlineFolders"] = nlohmann::json::array();
            return false;
        }

        nlohmann::json& offline_folders = m_vault_data["offlineFolders"];

        return std::find(offline_folders.begin(), offline_folders.end(), uuid) != offline_folders.end();
    }

    std::expected<std::vector<ItemId>, RuntimeError> BitwardenRuntime::getMarkedItems() {
        if (!m_init) {
            return std::unexpected(RuntimeError::Uninitialised);
        }
        
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        
        if (!m_vault_data.contains("offlineItems") || !m_vault_data["offlineItems"].is_array()) {
            m_vault_data["offlineItems"] = nlohmann::json::array();
            return {};
        }

        return m_vault_data["offlineItems"].get<std::vector<ItemId>>();
    }

    std::expected<std::vector<ItemId>, RuntimeError> BitwardenRuntime::getMarkedFolders() {
        if (!m_init) {
            return std::unexpected(RuntimeError::Uninitialised);
        }
        
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        
        if (!m_vault_data.contains("offlineFolders") || !m_vault_data["offlineFolders"].is_array()) {
            m_vault_data["offlineFolders"] = nlohmann::json::array();
            return {};
        }

        return m_vault_data["offlineFolders"].get<std::vector<ItemId>>();
    }

    std::expected<Profile, RuntimeError> BitwardenRuntime::getProfile() {
        if (!m_init) {
            return std::unexpected(RuntimeError::Uninitialised);
        }
        
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        
        if (!m_vault_data.contains("profile") || !m_vault_data["profile"].is_object()) {
            return std::unexpected(RuntimeError::InvalidVault);
        }

        nlohmann::json& profile = m_vault_data["profile"];

        if (!profile.contains("email") || !profile["email"].is_string() ||
            !profile.contains("name") || !profile["name"].is_string() ||
            !profile.contains("premium") || !profile["premium"].is_bool() ||
            !profile.contains("organizations") ||
            !profile.contains("twoFactorEnabled") || !profile["twoFactorEnabled"].is_bool() ||
            !profile.contains("securityStamp") || !profile["securityStamp"].is_string() ||
            !profile.contains("creationDate") || !profile["creationDate"].is_string() ||
            !profile.contains("avatarColor") || !profile["avatarColor"].is_string()) {
            return std::unexpected(RuntimeError::InvalidVault);
        }

        Profile result;
        result.email = utils::getSecureVector(profile["email"]);
        result.name = utils::getSecureVector(profile["name"]);
        result.premium = profile["premium"];
        result.multi_factor_enabled = profile["twoFactorEnabled"];
        result.security_stamp = utils::getSecureVector(profile["securityStamp"]);
        result.creation_date = utils::s_getTime(profile["creationDate"]);
        result.avatar_color = profile["avatarColor"];

        if (profile["organizations"].is_array()) {
            for (nlohmann::json org : profile["organizations"]) {
                if (!org.contains("id") || !org["id"].is_string() ||
                    !org.contains("name") || !org["name"].is_string() ||
                    !org.contains("type") || !org["type"].is_number() ||
                    !org.contains("enabled") || !org["enabled"].is_bool()) {
                    continue;
                }

                OrganisationMembership membership;
                membership.id = org["id"];
                membership.name = utils::getSecureVector(org["name"]);
                membership.role = static_cast<OrganisationRole>(org["type"]);
                membership.enabled = org["enabled"];

                result.organisations.push_back(membership);
            }
        }

        return result;
    }

    std::expected<nlohmann::json, RuntimeError> BitwardenRuntime::getVaultInfo() {
        if (!m_init) {
            return std::unexpected(RuntimeError::Uninitialised);
        }
        
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        
        if (!m_vault_data.contains("userDecryption") || !m_vault_data["userDecryption"].is_object()) {
            return std::unexpected(RuntimeError::InvalidVault);
        }

        return m_vault_data["userDecryption"];
    }
        
    std::expected<Botan::secure_vector<uint8_t>, RuntimeError> BitwardenRuntime::getVersion() {
        if (!m_init) {
            return std::unexpected(RuntimeError::Uninitialised);
        }
        
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        
        if (!m_vault_data.contains("version") || !m_vault_data["version"].is_string()) {
            return std::unexpected(RuntimeError::InvalidVault);
        }

        return utils::getSecureVector(m_vault_data["version"]);
    }
    
    RuntimeError BitwardenRuntime::storeVersion(Botan::secure_vector<uint8_t> version) {
        if (!m_init) {
            return RuntimeError::Uninitialised;
        }
        
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        
        m_vault_data["version"] = utils::getString(version);
        
        if (!m_storage.write("vault.json", m_vault_data.dump(4)).has_value()) {
            return RuntimeError::StorageFailure;
        }

        return RuntimeError::Success;
    }

    Vendor BitwardenRuntime::getVendor() {
        return Vendor::BitWarden;
    }
}