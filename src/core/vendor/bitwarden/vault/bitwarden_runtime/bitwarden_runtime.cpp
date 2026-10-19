#include "bitwarden_runtime.h"

namespace clientwarden::vendor::bitwarden::vault {
    BitwardenRuntime::BitwardenRuntime(std::shared_ptr<Storage> storage) : Runtime(storage) {
        
    }

    /**
     * @brief Load Vault searches for the vault.json using m_storage which stores vaults in a uuid
     *  like system, eg: 0000-0000.../vault.json.
     * @note LoadVault must be run before calling any other funcs.
     */
    RuntimeError BitwardenRuntime::loadVault() {
        if (!m_storage->exists("vault.json")) {
            return RuntimeError::VaultNotFound;
        }

        std::string vault_data = utils::getString(m_storage->read("vault.json"));

        if (!nlohmann::json::accept(vault_data)) {
            return RuntimeError::InvalidVault;
        }

        std::lock_guard<std::recursive_mutex> lock(m_mutex);

        m_vault_data = nlohmann::json::parse(vault_data);

        if (!m_vault_data.is_object()) {
            return RuntimeError::InvalidVault;
        }

        m_init = true;

        return RuntimeError::Success;
    }

    /**
     * @brief Returns the m_vault_data if its initialised.
     */
    std::expected<nlohmann::json, RuntimeError> BitwardenRuntime::getVaultData() {
        if (!m_init) {
            return std::unexpected(RuntimeError::Uninitialised);
        }

        std::lock_guard<std::recursive_mutex> lock(m_mutex);

        return m_vault_data;
    }

    /**
     * @brief Returns an array of ciphers in nlohmann::json.
     */
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

    /**
     * @brief Returns a vector list of all the Item Ids in the ciphers.
     */
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
            ids.push_back(c_id);
        }

        return ids;
    }

    /**
     * @brief Returns an nlohmann::json of the cipher that matches the id.
     */
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
    
    /**
     * @note If the item is being updated offline, an update item record should be marked first.
     * @note Runtime should not modify or call any record funcs. Instead, the Orchestrator should
     *  call the record.
     * @note updateItem shouldn't replace uuid unless necessary to allow for remapping ids.
     */
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

            if (cipher["id"] == uuid) {
                cipher = std::move(item);

                if (!cipher.contains("id") || !cipher["id"].is_string()) {
                    cipher["id"] = uuid;
                }

                if (!m_storage->write("vault.json", m_vault_data.dump(4)).has_value()) {
                    return RuntimeError::StorageFailure;
                }

                return RuntimeError::Success;
            }
        }

        return RuntimeError::NotFound;
    }

    /**
     * @brief Check if ciphers exists and the item is valid and if it doesnt exist already, then
     *  push to ciphers and update.
     */
    RuntimeError BitwardenRuntime::addItem(nlohmann::json item) {
        if (!m_init) {
            return RuntimeError::Uninitialised;
        }
        
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        
        if (!m_vault_data.contains("ciphers") || !m_vault_data["ciphers"].is_array()) {
            return RuntimeError::InvalidVault;
        }

        if (!item.contains("id") || !item["id"].is_string()) {
            return RuntimeError::InvalidParams;
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
        
        if (!m_storage->write("vault.json", m_vault_data.dump(4)).has_value()) {
            return RuntimeError::StorageFailure;
        }

        return RuntimeError::Success;
    }

    /**
     * @brief Use a cipher iterator to find and remove the item and write to the vault json.
     */
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
        
        if (!m_storage->write("vault.json", m_vault_data.dump(4)).has_value()) {
            return RuntimeError::StorageFailure;
        }

        return RuntimeError::Success;
    }

    /**
     * @brief Check if folders array is valid and loop through folders and return a vector of item
     *  ids.
     */
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
            ids.push_back(c_id);
        }

        return ids;
    }

    /**
     * @brief Loop through all the folders to find a matching uuid and return folder.
     */
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

    /**
     * @brief Loop through all the folders and replace the folder with the matching id.
     * @note If the folder is being updated offline, an update folder record should be marked first.
     */
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

            if (folder["id"] == uuid) {
                folder = std::move(folder_item);

                if (!folder.contains("id") || !folder["id"].is_string()) {
                    folder["id"] = uuid;
                }
                
                if (!m_storage->write("vault.json", m_vault_data.dump(4)).has_value()) {
                    return RuntimeError::StorageFailure;
                }

                return RuntimeError::Success;
            }
        }

        return RuntimeError::NotFound;
    }

    /**
     * @brief Check if folders array and folder_item is valid and check if it already exists, then
     *  add to folder array and write to vault.
     */
    RuntimeError BitwardenRuntime::addFolder(nlohmann::json folder_item) {
        if (!m_init) {
            return RuntimeError::Uninitialised;
        }
        
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        
        if (!m_vault_data.contains("folders") || !m_vault_data["folders"].is_array()) {
            return RuntimeError::InvalidVault;
        }

        if (!folder_item.contains("id") || !folder_item["id"].is_string()) {
            return RuntimeError::InvalidParams;
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
        
        if (!m_storage->write("vault.json", m_vault_data.dump(4)).has_value()) {
            return RuntimeError::StorageFailure;
        }

        return RuntimeError::Success;
    }

    /**
     * @brief Loop through all the folders and erase the folder with the matchin uuid.
     */
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
        
        if (!m_storage->write("vault.json", m_vault_data.dump(4)).has_value()) {
            return RuntimeError::StorageFailure;
        }

        return RuntimeError::Success;
    }

    /**
     * @brief Find the cipher with the uuid and push the attachment to the attchments array and write to
     *  vault.
     * @note If the attachment is being updated offline, an update attachment record should be marked first.
     */
    RuntimeError BitwardenRuntime::addAttachment(ItemId uuid, nlohmann::json attachment) {
        if (!m_init) {
            return RuntimeError::Uninitialised;
        }

        if (!attachment.contains("id") || !attachment["id"].is_string()) {
            return RuntimeError::InvalidParams;
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

            if (cipher["id"] == uuid) {
                if (!cipher.contains("attachments") || !cipher["attachments"].is_array()) {
                    cipher["attachments"] = nlohmann::json::array();
                }

                for (const nlohmann::json& existing : cipher["attachments"]) {
                    if (existing.is_object() && existing.contains("id") && existing["id"].is_string() &&
                        existing["id"] == attachment["id"]) {
                        return RuntimeError::ExistingItem;
                    }
                }

                cipher["attachments"].push_back(attachment);

                if (!cipher.contains("id") || !cipher["id"].is_string()) {
                    cipher["id"] = uuid;
                }

                if (!m_storage->write("vault.json", m_vault_data.dump(4)).has_value()) {
                    return RuntimeError::StorageFailure;
                }

                return RuntimeError::Success;
            }
        }

        return RuntimeError::NotFound;
    }


    /**
     * @brief Find the attachment with the uuid and attachment id and replace it.
     * @note If the attachment is being updated offline, an update item record should be marked first.
     */
    RuntimeError BitwardenRuntime::updateAttachment(ItemId uuid, ItemId attachment_id, nlohmann::json attachment) {
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

            if (cipher["id"] == uuid) {
                if (!cipher.contains("attachments") || !cipher["attachments"].is_array()) {
                    return RuntimeError::NotFound;
                }

                bool replaced = false;

                for (nlohmann::json& cipher_attachment : cipher["attachments"]) {
                    if (!cipher_attachment.is_object() || !cipher_attachment.contains("id") || 
                        !cipher_attachment["id"].is_string()) {
                        continue;
                    }

                    if (cipher_attachment["id"] == attachment_id) {
                        cipher_attachment = attachment;

                        if (!cipher_attachment.contains("id") || 
                            !cipher_attachment["id"].is_string()) {
                            cipher_attachment["id"] = attachment_id;
                        }
                        replaced = true;
                        break;
                    }
                }

                if (!replaced) {
                    return RuntimeError::NotFound;
                }

                if (!m_storage->write("vault.json", m_vault_data.dump(4)).has_value()) {
                    return RuntimeError::StorageFailure;
                }

                return RuntimeError::Success;
            }
        }

        return RuntimeError::NotFound;
    }

    /**
     * @brief Find the attacment with the uuid and attachment_id and remove it.
     * @note If the attachment is being removed offline, an update item record should be marked first.
     * @note While Attachments are stored with an `id`, network expects an `attachmentId`.
     */
    RuntimeError BitwardenRuntime::removeAttachment(ItemId uuid, ItemId attachment_id) {
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

            if (cipher["id"] == uuid) {
                if (!cipher.contains("attachments") || !cipher["attachments"].is_array()) {
                    return RuntimeError::NotFound;
                }

                nlohmann::json& attachments = cipher["attachments"];
                bool removed = false;

                for (size_t i = 0; i < attachments.size(); ++i) {
                    if (!attachments[i].is_object() || !attachments[i].contains("id") || 
                        !attachments[i]["id"].is_string()) {
                        continue;
                    }

                    if (attachments[i]["id"] == attachment_id) {
                        attachments.erase(i);
                        removed = true;
                        break;
                    }
                }

                if (!removed) {
                    return RuntimeError::NotFound;
                }

                if (!m_storage->write("vault.json", m_vault_data.dump(4)).has_value()) {
                    return RuntimeError::StorageFailure;
                }

                return RuntimeError::Success;
            }
        }

        return RuntimeError::NotFound;
    }

    /**
     * @brief First, find the item with the matching uuid and then return the attachment with the
     *  matching attachment_id.
     */
    std::expected<nlohmann::json, RuntimeError> BitwardenRuntime::getAttachment(ItemId uuid, ItemId attachment_id) {
        if (!m_init) {
            return std::unexpected(RuntimeError::Uninitialised);
        }
        
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        
        nlohmann::json::iterator ciphers_iterator = m_vault_data.find("ciphers");

        if (ciphers_iterator == m_vault_data.end() || !ciphers_iterator->is_array()) {
            return std::unexpected(RuntimeError::InvalidVault);
        }

        for (nlohmann::json& cipher : *ciphers_iterator) {
            if (!cipher.contains("id") || !cipher["id"].is_string()) {
                continue;
            }

            if (cipher["id"] == uuid) {
                if (!cipher.contains("attachments") || !cipher["attachments"].is_array()) {
                    return std::unexpected(RuntimeError::NotFound);
                }

                for (nlohmann::json& cipher_attachment : cipher["attachments"]) {
                    if (!cipher_attachment.is_object() || !cipher_attachment.contains("id") || 
                        !cipher_attachment["id"].is_string()) {
                        continue;
                    }

                    if (cipher_attachment["id"] == attachment_id) {
                        return cipher_attachment;
                    }
                }

                return std::unexpected(RuntimeError::NotFound);
            }
        }

        return std::unexpected(RuntimeError::NotFound);
    }

    std::expected<std::vector<ItemId>, RuntimeError> BitwardenRuntime::getAttachmentIds(ItemId uuid) {
        if (!m_init) {
            return std::unexpected(RuntimeError::Uninitialised);
        }

        std::vector<ItemId> result;
        
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        
        nlohmann::json::iterator ciphers_iterator = m_vault_data.find("ciphers");

        if (ciphers_iterator == m_vault_data.end() || !ciphers_iterator->is_array()) {
            return std::unexpected(RuntimeError::InvalidVault);
        }

        for (nlohmann::json& cipher : *ciphers_iterator) {
            if (!cipher.contains("id") || !cipher["id"].is_string()) {
                continue;
            }

            if (cipher["id"] == uuid) {
                if (!cipher.contains("attachments") || !cipher["attachments"].is_array()) {
                    return result;
                }

                for (nlohmann::json& cipher_attachment : cipher["attachments"]) {
                    if (!cipher_attachment.is_object() || !cipher_attachment.contains("id") || 
                        !cipher_attachment["id"].is_string()) {
                        continue;
                    }

                    result.push_back(cipher_attachment["id"]);
                }

                return result;
            }
        }

        return std::unexpected(RuntimeError::NotFound);
    }

    /**
     * @brief First, create pending.created, pending.createdPartial, pending.updated, etc. Then, 
     *  create a record_json that contains the revision date, itemtype and id. If the attachment is
     *  created, then push to created. If its Created partial, then remove from created and push to 
     *  created partial. If its updated and already exists, then update the revisionDate, else, 
     *  update the base and add the record_json to updated. If its deleted, then remove from
     *  created and add to deleted and remove from updated.
     * @note Only 1 record can exist of the item type.
     * @note Attachments must contains a parent id.
     */
    RuntimeError BitwardenRuntime::record(PendingChange change) {
        if (!m_init) {
            return RuntimeError::Uninitialised;
        }

        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        
        if (!m_vault_data.contains("pending") || !m_vault_data["pending"].is_object()) {
            m_vault_data["pending"] = nlohmann::json::object();
        }

        if (!m_vault_data["pending"].contains("created") || 
            !m_vault_data["pending"]["created"].is_object()) {
            m_vault_data["pending"]["created"] = nlohmann::json::object();
        }

        if (!m_vault_data["pending"].contains("createdPartial") || 
            !m_vault_data["pending"]["createdPartial"].is_object()) {
            m_vault_data["pending"]["createdPartial"] = nlohmann::json::object();
        }

        if (!m_vault_data["pending"].contains("updated") || 
            !m_vault_data["pending"]["updated"].is_object()) {
            m_vault_data["pending"]["updated"] = nlohmann::json::object();
        }

        if (!m_vault_data["pending"].contains("deleted") || 
            !m_vault_data["pending"]["deleted"].is_object()) {
            m_vault_data["pending"]["deleted"] = nlohmann::json::object();
        }

        nlohmann::json& created = m_vault_data["pending"]["created"];
        nlohmann::json& created_partial = m_vault_data["pending"]["createdPartial"];
        nlohmann::json& updated = m_vault_data["pending"]["updated"];
        nlohmann::json& deleted = m_vault_data["pending"]["deleted"];

        ItemId entity_id = change.entity.id;

        if (change.entity.type == EntityType::Attachment) {
            if (change.entity.parent_id.empty()) {
                return RuntimeError::InvalidParams;
            }

            entity_id = change.entity.id + "/" + change.entity.parent_id;
        }

        /**
         * @note No items should exist in the same bucket.
         * @note Created allows no exising records, CreatedPartial only allows a Created existing
         *  record, Updated allows no existing records except for updated, Deleted only allows a 
         *  Created, Created Partial and Updated existing records.
         */

        std::vector<std::reference_wrapper<const nlohmann::json>> buckets_to_check;
        if (change.type == ChangeType::Created) {
            buckets_to_check = { created, created_partial, updated, deleted };
        } else if (change.type == ChangeType::CreatedPartial) {
            buckets_to_check = { created_partial, updated, deleted };
        } else if (change.type == ChangeType::Updated) {
            buckets_to_check = { created, created_partial, deleted };
        } else if (change.type == ChangeType::Deleted) {
            buckets_to_check = { deleted };
        }

        for (const nlohmann::json& bucket : buckets_to_check) {
            if (bucket.contains(entity_id)) {
                return RuntimeError::ExistingItem;
            }
        }
        
        /**
         * @note We dont need to store the id and parentId since thats in the entityId, but its
         *  good practice and makes things easier.
         */
        nlohmann::json record_json;
        record_json["revisionDate"] = change.revision_date;
        record_json["itemType"] = getString(change.entity.type);
        record_json["id"] = change.entity.id;

        if (change.entity.type == EntityType::Attachment) {
            record_json["parentId"] = change.entity.parent_id;
        }

        switch (change.type) {
            case ChangeType::Created:
                if (change.entity.type == EntityType::Attachment) {
                    record_json["base"] = change.base;
                }
                
                created[entity_id] = record_json;
                break;
            case ChangeType::CreatedPartial:
                created.erase(entity_id);
                created_partial[entity_id] = record_json;
                break;
            case ChangeType::Updated:
                if (updated.contains(entity_id)) {
                    updated[entity_id]["revisionDate"] = change.revision_date;
                } else {
                    record_json["base"] = change.base;
                    updated[entity_id] = record_json;
                }
                break;
            case ChangeType::Deleted:
                /**
                 * @brief If it was created locally, then we can safely remove it from the record
                 *  storage.
                 */
                if (created.contains(entity_id)) {
                    created.erase(entity_id);
                    break;
                }

                created_partial.erase(entity_id);
                updated.erase(entity_id);
                record_json["base"] = change.base;
                deleted[entity_id] = record_json;
                break;
            default:
                return RuntimeError::InvalidParams;
        }

        /**
         * @brief If an item is being deleted, then delete all the attachment records.
         * @note When an item is deleted online, all the attachments get removed as well, so you
         *  dont have to manually delete the attachments.
         */
        if (change.type == ChangeType::Deleted && change.entity.type == EntityType::Item) {
            nlohmann::json& pending = m_vault_data["pending"];
            
            for (std::string name : {"created", "createdPartial", "updated", "deleted"}) {
                nlohmann::json::iterator bucket = pending.find(name);
                if (bucket == pending.end() || !bucket->is_object()) {
                    continue;
                }

                std::vector<ItemId> removal_ids;

                for (nlohmann::json::iterator iterator = bucket->begin(); iterator != bucket->end(); ++iterator) {
                    if (!iterator.value().is_object() || !iterator.value().contains("itemType") ||
                        !iterator.value()["itemType"].is_string() || 
                        !iterator.value().contains("parentId") || 
                        !iterator.value()["parentId"].is_string()) {
                        continue;
                    }

                    if (iterator.value()["itemType"] == "attachment" &&
                        iterator.value()["parentId"] == change.entity.id) {
                        removal_ids.push_back(iterator.key());
                    }
                }

                for (ItemId key : removal_ids) {
                    bucket->erase(key);
                }
            }
        }

        if (!m_storage->write("vault.json", m_vault_data.dump(4)).has_value()) {
            return RuntimeError::StorageFailure;
        }

        return RuntimeError::Success;
    }

    /**
     * @brief To remove the record, we need to loop through all the buckets and erase them.
     */
    RuntimeError BitwardenRuntime::removeRecord(Entity entity) {
        if (!m_init) {
            return RuntimeError::Uninitialised;
        }

        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        
        if (!m_vault_data.contains("pending") || !m_vault_data["pending"].is_object()) {
            return RuntimeError::NotFound;
        }

        ItemId entity_id = entity.id;
        if (entity.type == EntityType::Attachment) {
            entity_id = entity.id + "/" + entity.parent_id;
        }

        bool found = false;

        nlohmann::json& pending = m_vault_data["pending"];
        
        for (std::string name : {"created", "createdPartial", "updated", "deleted"}) {
            nlohmann::json::iterator bucket = pending.find(name);
            if (bucket == pending.end() || !bucket->is_object()) {
                continue;
            }

            if (bucket->erase(entity_id) > 0) {
                found = true;
            }
        }

        if (!found) {
            return RuntimeError::NotFound;
        }

        if (!m_storage->write("vault.json", m_vault_data.dump(4)).has_value()) {
            return RuntimeError::StorageFailure;
        }

        return RuntimeError::Success;
    }

    /**
     * @brief To find the record, we need to get the entityId and loop through all the bucks and
     *  find the matching record with the entity_id.
     */
    std::expected<PendingChange, RuntimeError> BitwardenRuntime::getRecord(Entity entity) {
        if (!m_init) {
            return std::unexpected(RuntimeError::Uninitialised);
        }

        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        
        if (!m_vault_data.contains("pending") || !m_vault_data["pending"].is_object()) {
            return std::unexpected(RuntimeError::NotFound);
        }

        ItemId entity_id = entity.id;
        if (entity.type == EntityType::Attachment) {
            entity_id = entity.id + "/" + entity.parent_id;
        }

        nlohmann::json pending = m_vault_data["pending"];
        
        for (std::string name : {"created", "createdPartial", "updated", "deleted"}) {
            for (auto& [item_id, value] : pending[name].items()) {
                if (item_id != entity_id) {
                    continue;
                }

                if (!value.contains("revisionDate") || !value["revisionDate"].is_string() ||
                    !value.contains("id") || !value["id"].is_string() ||
                    !value.contains("itemType") || !value["itemType"].is_string()) {
                    return std::unexpected(RuntimeError::InvalidVault);
                }

                PendingChange change;
                change.revision_date = value["revisionDate"];
                change.entity.id = value["id"];
                change.entity.type = getEntityType(value.value("itemType", ""));
                change.type = getChangeType(name);

                if (change.entity.type == EntityType::Attachment && 
                    value.contains("parentId") && value["parentId"].is_string()) {
                    change.entity.parent_id = value["parentId"];
                }

                if (value.contains("base") && value["base"].is_object()) {
                    change.base = value["base"];
                } else if (name == "updated") {
                    return std::unexpected(RuntimeError::InvalidVault);
                }

                return change;
            }
        }

        return std::unexpected(RuntimeError::NotFound);
    }

    /**
     * @brief To check if a record exists, we can loop through all the buckets and find one with 
     *  the matching entity id.
     */
    std::expected<bool, RuntimeError> BitwardenRuntime::recordExists(Entity entity) {
        if (!m_init) {
            return std::unexpected(RuntimeError::Uninitialised);
        }
        
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        
        if (!m_vault_data.contains("pending") || !m_vault_data["pending"].is_object()) {
            return false;
        }

        ItemId entity_id = entity.id;
        if (entity.type == EntityType::Attachment) {
            entity_id = entity.id + "/" + entity.parent_id;
        }

        nlohmann::json& pending = m_vault_data["pending"];
        
        for (std::string name : {"created", "createdPartial", "updated", "deleted"}) {
            nlohmann::json::const_iterator bucket = pending.find(name);
            if (bucket != pending.cend() && bucket->is_object() && bucket->contains(entity_id)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @brief If its unknown, add all buckets to the names vector and then loop through all the
     *  records and create the Pending Change and add them to the vector.
     */
    std::expected<std::vector<PendingChange>, RuntimeError> BitwardenRuntime::getAllRecords(
        ChangeType type) {
        
        if (!m_init) {
            return std::unexpected(RuntimeError::Uninitialised);
        }

        std::lock_guard<std::recursive_mutex> lock(m_mutex);

        std::vector<PendingChange> result;
        
        if (!m_vault_data.contains("pending") || !m_vault_data["pending"].is_object()) {
            return result;
        }

        nlohmann::json pending = m_vault_data["pending"];

        std::vector<std::string> names;
        if (type == ChangeType::Unknown) {
            names = {"created", "createdPartial", "updated", "deleted"};
        } else {
            names.push_back(std::string(getString(type)));
        }
        
        for (std::string name : names) {
            for (auto& [item_id, value] : pending[name].items()) {
                if (!value.contains("revisionDate") || !value["revisionDate"].is_string() ||
                    !value.contains("id") || !value["id"].is_string() ||
                    !value.contains("itemType") || !value["itemType"].is_string()) {
                    continue;
                }

                PendingChange change;
                change.revision_date = value["revisionDate"];
                change.entity.id = value["id"];
                change.entity.type = getEntityType(value.value("itemType", ""));
                change.type = getChangeType(name);

                if (change.entity.type == EntityType::Attachment && 
                    value.contains("parentId") && value["parentId"].is_string()) {
                    change.entity.parent_id = value["parentId"];
                }

                if (value.contains("base") && value["base"].is_object()) {
                    change.base = value["base"];
                } else if (name == "updated") {
                    continue;
                }

                result.push_back(change);
            }
        }

        return result;
    }

    /**
     * @brief Check if the vault profile is valid, then build the profile using the json vault.
     */
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
            !profile.contains("id") || !profile["id"].is_string() ||
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
        result.id = profile["id"];
        result.premium = profile["premium"];
        result.multi_factor_enabled = profile["twoFactorEnabled"];
        result.security_stamp = utils::getSecureVector(profile["securityStamp"]);
        result.creation_date = utils::s_getTime(profile["creationDate"]);
        result.avatar_color = profile["avatarColor"];
        result.raw = profile;

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

    /**
     * @brief Check if `userDecryption` is valid and then return.
     */
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
    
    /**
     * @brief Check if a version key exists, and then return it.
     */
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
    
    /**
     * @brief Store a version key.
     */
    RuntimeError BitwardenRuntime::storeVersion(Botan::secure_vector<uint8_t> version) {
        if (!m_init) {
            return RuntimeError::Uninitialised;
        }
        
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        
        m_vault_data["version"] = utils::getString(version);
        
        if (!m_storage->write("vault.json", m_vault_data.dump(4)).has_value()) {
            return RuntimeError::StorageFailure;
        }

        return RuntimeError::Success;
    }

    Vendor BitwardenRuntime::getVendor() {
        return Vendor::BitWarden;
    }
}