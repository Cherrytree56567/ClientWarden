#include "bitwarden_query.h"

namespace clientwarden {
    BitwardenQuery::BitwardenQuery(Vault& vault) : Query(vault) {
        std::expected<std::vector<ItemId>, RuntimeError> item_ids_err = 
            m_vault.getOrchestrator()->getRuntime()->getItemIds();
        
        if (!item_ids_err.has_value()) {
            return;
        }

        item_ids = item_ids_err.value();
        m_init = true;
    }

    BitwardenQuery::~BitwardenQuery() {
        item_ids.clear();
        m_init = false;
    }

    BitwardenQuery& BitwardenQuery::filterByType(ItemType type) {
        if (!m_init) {
            return *this;
        }

        std::erase_if(item_ids, [&](const ItemId& item_id) {
            std::expected<nlohmann::json, RuntimeError> item_err = 
                m_vault.getOrchestrator()->getRuntime()->getItem(item_id);
            
            if (!item_err.has_value()) {
                return true;
            }

            if (!item_err.value().contains("type") || 
                !item_err.value()["type"].is_number_integer()) {
                return true;
            }

            return item_err.value()["type"] != static_cast<int>(type); 
        });

        return *this;
    }
    
    BitwardenQuery& BitwardenQuery::filterByCreationDate(Timestamp start, Timestamp end) {
        if (!m_init) {
            return *this;
        }
        
        std::erase_if(item_ids, [&](const ItemId& item_id) {
            std::expected<nlohmann::json, RuntimeError> item_err = 
                m_vault.getOrchestrator()->getRuntime()->getItem(item_id);
            
            if (!item_err.has_value()) {
                return true;
            }

            if (!item_err.value().contains("creationDate") || 
                !item_err.value()["creationDate"].is_string()) {
                return true;
            }

            Timestamp creation_time = utils::s_getTime(item_err.value()["creationDate"]);

            return (creation_time < start) || (creation_time > end); 
        });

        return *this;
    }
    
    BitwardenQuery& BitwardenQuery::filterByRevisionDate(Timestamp start, Timestamp end) {
        if (!m_init) {
            return *this;
        }
        
        std::erase_if(item_ids, [&](const ItemId& item_id) {
            std::expected<nlohmann::json, RuntimeError> item_err = 
                m_vault.getOrchestrator()->getRuntime()->getItem(item_id);
            
            if (!item_err.has_value()) {
                return true;
            }

            if (!item_err.value().contains("revisionDate") || 
                !item_err.value()["revisionDate"].is_string()) {
                return true;
            }

            Timestamp revision_time = utils::s_getTime(item_err.value()["revisionDate"]);

            return (revision_time < start) || (revision_time > end); 
        });

        return *this;
    }
    
    BitwardenQuery& BitwardenQuery::filterByDeletionDate(Timestamp start, Timestamp end) {
        if (!m_init) {
            return *this;
        }
        
        std::erase_if(item_ids, [&](const ItemId& item_id) {
            std::expected<nlohmann::json, RuntimeError> item_err = 
                m_vault.getOrchestrator()->getRuntime()->getItem(item_id);
            
            if (!item_err.has_value()) {
                return true;
            }

            if (!item_err.value().contains("deletedDate") || 
                !item_err.value()["deletedDate"].is_string()) {
                return true;
            }

            Timestamp deletion_time = utils::s_getTime(item_err.value()["deletedDate"]);

            return (deletion_time < start) || (deletion_time > end); 
        });

        return *this;
    }
    
    BitwardenQuery& BitwardenQuery::filterByPasskey() {
        if (!m_init) {
            return *this;
        }
        
        std::erase_if(item_ids, [&](const ItemId& item_id) {
            std::expected<nlohmann::json, RuntimeError> item_err = 
                m_vault.getOrchestrator()->getRuntime()->getItem(item_id);
            
            if (!item_err.has_value()) {
                return true;
            }

            if (!item_err.value().contains("type") || 
                !item_err.value()["type"].is_number_integer() || 
                !item_err.value().contains("login") || 
                !item_err.value()["login"].is_object() || 
                !item_err.value()["login"].contains("fido2Credentials") || 
                !item_err.value()["login"]["fido2Credentials"].is_array()) {
                return true;
            }

            if (item_err.value()["type"] != static_cast<int>(ItemType::Login)) {
                return true;
            }

            return item_err.value()["login"]["fido2Credentials"].empty();
        });

        return *this;
    }
    
    BitwardenQuery& BitwardenQuery::filterByBinned() {
        if (!m_init) {
            return *this;
        }
        
        std::erase_if(item_ids, [&](const ItemId& item_id) {
            std::expected<nlohmann::json, RuntimeError> item_err = 
                m_vault.getOrchestrator()->getRuntime()->getItem(item_id);
            
            if (!item_err.has_value()) {
                return true;
            }

            if (!item_err.value().contains("deletedDate") || 
                !item_err.value()["deletedDate"].is_string()) {
                return true;
            }

            return false;
        });

        return *this;
    }
    
    BitwardenQuery& BitwardenQuery::filterByUnbinned() {
        if (!m_init) {
            return *this;
        }
        
        std::erase_if(item_ids, [&](const ItemId& item_id) {
            std::expected<nlohmann::json, RuntimeError> item_err = 
                m_vault.getOrchestrator()->getRuntime()->getItem(item_id);
            
            if (!item_err.has_value()) {
                return true;
            }

            if (!item_err.value().contains("deletedDate") || 
                !item_err.value()["deletedDate"].is_string()) {
                return false;
            }

            return true;
        });

        return *this;
    }
    
    BitwardenQuery& BitwardenQuery::filterByArchived() {
        if (!m_init) {
            return *this;
        }
        
        std::erase_if(item_ids, [&](const ItemId& item_id) {
            std::expected<nlohmann::json, RuntimeError> item_err = 
                m_vault.getOrchestrator()->getRuntime()->getItem(item_id);
            
            if (!item_err.has_value()) {
                return true;
            }

            if (!item_err.value().contains("archivedDate") || 
                !item_err.value()["archivedDate"].is_string()) {
                return true;
            }

            return false;
        });

        return *this;
    }
    
    BitwardenQuery& BitwardenQuery::filterByUnarchived() {
        if (!m_init) {
            return *this;
        }
        
        std::erase_if(item_ids, [&](const ItemId& item_id) {
            std::expected<nlohmann::json, RuntimeError> item_err = 
                m_vault.getOrchestrator()->getRuntime()->getItem(item_id);
            
            if (!item_err.has_value()) {
                return true;
            }

            if (!item_err.value().contains("archivedDate") || 
                !item_err.value()["archivedDate"].is_string()) {
                return false;
            }

            return true;
        });

        return *this;
    }
    
    BitwardenQuery& BitwardenQuery::filterByFavorites() {
        if (!m_init) {
            return *this;
        }
        
        std::erase_if(item_ids, [&](const ItemId& item_id) {
            std::expected<nlohmann::json, RuntimeError> item_err = 
                m_vault.getOrchestrator()->getRuntime()->getItem(item_id);
            
            if (!item_err.has_value()) {
                return true;
            }

            if (!item_err.value().contains("favorite") || 
                !item_err.value()["favorite"].is_bool()) {
                return true;
            }

            return !item_err.value()["favorite"];
        });

        return *this;
    }
    
    BitwardenQuery& BitwardenQuery::filterByGroup(ItemId group_id) {
        if (!m_init) {
            return *this;
        }
        
        std::erase_if(item_ids, [&](const ItemId& item_id) {
            std::expected<nlohmann::json, RuntimeError> item_err = 
                m_vault.getOrchestrator()->getRuntime()->getItem(item_id);
            
            if (!item_err.has_value()) {
                return true;
            }

            if (group_id == "00000000-0000-0000-0000-000000000000") {
                return item_err.value().contains("folderId") &&
                    item_err.value()["folderId"].is_string();
            }

            if (!item_err.value().contains("folderId") || 
                !item_err.value()["folderId"].is_string()) {
                return true;
            }

            return item_err.value()["folderId"] != group_id;
        });

        return *this;
    }
    
    BitwardenQuery& BitwardenQuery::filterNameByRegex(std::string regex) {
        if (!m_init) {
            return *this;
        }

        std::regex pattern;
        try {
            pattern = std::regex(regex, std::regex_constants::icase | std::regex_constants::nosubs);
        } catch (const std::regex_error&) {
            return *this;
        }

        std::erase_if(item_ids, [&](const ItemId& item_id) {
            std::expected<nlohmann::json, RuntimeError> item_err = 
                m_vault.getOrchestrator()->getRuntime()->getItem(item_id);
            
            if (!item_err.has_value()) {
                return true;
            }

            if (!item_err.value().contains("name") || 
                !item_err.value()["name"].is_string()) {
                return true;
            }

            ItemKey key;

            if (item_err.value().contains("key") &&
                item_err.value()["key"].is_string()) {
                std::expected<ItemKey, CryptoErrors> item_key_err = 
                    m_vault.getOrchestrator()->getCrypto()->resolveItemKey(
                        utils::getSecureVector(item_err.value()["key"])
                    );
                
                if (!item_key_err.has_value()) {
                    return true;
                }

                key = std::move(item_key_err.value());
            } else {
                std::expected<ItemKey, CryptoErrors> item_key_err = 
                    m_vault.getOrchestrator()->getCrypto()->getItemKeys();
                
                if (!item_key_err.has_value()) {
                    return true;
                }

                key = std::move(item_key_err.value());
            }

            std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> name_err = 
                m_vault.getOrchestrator()->getCrypto()->decrypt(
                    utils::getSecureVector(item_err.value()["name"]), key
                );
            
            key.clear();
            
            if (!name_err.has_value()) {
                return true;
            }

            const char* begin_name = reinterpret_cast<const char*>(name_err.value().data());
            const char* end_name = begin_name + name_err.value().size();

            if (!std::regex_search(begin_name, end_name, pattern)) {
                /**
                 * @note Just learnt abt this.
                 */
                Botan::zap(name_err.value());

                return true;
            } else {
                Botan::zap(name_err.value());

                return false;
            }
        });

        return *this;
    }

    std::expected<std::vector<ItemId>, QueryError> BitwardenQuery::get() {
        if (!m_init) {
            return std::unexpected(QueryError::Uninitialised);
        }
        
        return item_ids;
    }
    
    std::expected<std::vector<std::pair<ItemType, ItemId>>, QueryError> BitwardenQuery::getItems() {
        if (!m_init) {
            return std::unexpected(QueryError::Uninitialised);
        }

        std::vector<std::pair<ItemType, ItemId>> result;

        for (ItemId item_id : item_ids) {
            std::expected<nlohmann::json, RuntimeError> item_err = 
                m_vault.getOrchestrator()->getRuntime()->getItem(item_id);
            
            if (!item_err.has_value()) {
                continue;
            }

            if (!item_err.value().contains("type") || 
                !item_err.value()["type"].is_number_integer()) {
                continue;
            }

            if (item_err.value()["type"] > 8 || item_err.value()["type"] < 0) {
                continue;
            }

            ItemType item_type = static_cast<ItemType>(item_err.value()["type"]);

            result.push_back(std::make_pair(item_type, item_id));
        }

        return result;
    }

    Vendor BitwardenQuery::getVendor() {
        return Vendor::BitWarden;
    }
}