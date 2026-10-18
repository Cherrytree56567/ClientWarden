#include "bitwarden_sync.h"

namespace clientwarden::vendor::bitwarden::vault {
    BitwardenSync::BitwardenSync(std::shared_ptr<Runtime> runtime, std::shared_ptr<Network> network, 
        std::shared_ptr<Settings> settings) : Sync(runtime, network, settings) {
        
    }

    std::expected<bool, SyncError> BitwardenSync::fullSync() {
        
    }
    
    std::expected<bool, SyncError> BitwardenSync::startSyncThread() {
        
    }
    
    std::expected<bool, SyncError> BitwardenSync::stopSyncThread() {
        
    }
    
    Vendor BitwardenSync::getVendor() {
        return Vendor::BitWarden;
    }

    /**
     * @brief First, we can get a vector of item and folder ids to loop through. Then, we need to
     *  get the item/folder json and create an entity to check if the record exists. Then we can
     *  create a create a SyncRecord. If its updated locally, then we need to get the revision
     *  date from the record. After all that, we can then get a list of all the records, and if the
     *  change type is deleted, we check if the record already exists. If not, then we create our
     *  sync record. If its not deleted and is an attachment which is created, then we make an
     *  attachment created record.
     */
    std::expected<std::vector<SyncRecord>, SyncError> BitwardenSync::fetchLocalRecords() {
        std::vector<SyncRecord> result;

        std::expected<std::vector<ItemId>, RuntimeError> item_ids = 
            m_runtime->getItemIds();
        
        if (!item_ids.has_value()) {
            return std::unexpected(SyncError::RuntimeError);
        }

        std::expected<std::vector<ItemId>, RuntimeError> folder_ids = 
            m_runtime->getFolders();
        
        if (!folder_ids.has_value()) {
            return std::unexpected(SyncError::RuntimeError);
        }

        for (EntityType type : { EntityType::Item, EntityType::Folder }) {
            const std::vector<ItemId>& ids = (type == EntityType::Item) ? item_ids.value()
                                                                        : folder_ids.value();
            for (ItemId item_id : ids) {
                std::expected<nlohmann::json, RuntimeError> item_json;

                if (type == EntityType::Item) {
                    item_json = m_runtime->getItem(item_id);
                } else {
                    item_json = m_runtime->getFolder(item_id);
                }
                
                if (!item_json.has_value() || !item_json.value().contains("revisionDate") ||
                    !item_json.value()["revisionDate"].is_string()) {
                    continue;
                }

                Entity entity;
                entity.type = type;
                entity.id = item_id;

                std::expected<bool, RuntimeError> is_local = 
                    m_runtime->recordExists(entity);
                
                if (!is_local.has_value()) {
                    /**
                     * @note We return an error here, bc if is_local fails, it means that m_runtime is
                     *  not initialised.
                     */
                    return std::unexpected(SyncError::RuntimeError);
                }

                SyncRecord record;
                record.item_type = (type == EntityType::Item) ? SyncItem::Item : SyncItem::Folder;
                record.uuid = item_id;
                record.revision = utils::s_getTime(item_json.value()["revisionDate"]);
                record.state = SyncState::Clean;
                record.raw = item_json.value();

                if (is_local.value()) {
                    std::expected<PendingChange, RuntimeError> pending_record =
                        m_runtime->getRecord(entity);
                    
                    if (!pending_record.has_value()) {
                        return std::unexpected(SyncError::RuntimeError);
                    }

                    if (pending_record.value().type == ChangeType::Updated) {
                        record.revision = utils::s_getTime(pending_record.value().revision_date);
                        record.state = SyncState::Modified;
                    } else if (pending_record.value().type == ChangeType::Created) {
                        record.state = SyncState::CreatedOffline;
                    } else if (pending_record.value().type == ChangeType::CreatedPartial) {
                        record.state = SyncState::CreatedOfflinePartially;
                    } else if (pending_record.value().type == ChangeType::Deleted) {
                        record.state = SyncState::PendingDelete;
                    }
                }

                result.push_back(record);
            }
        }

        std::expected<std::vector<PendingChange>, RuntimeError> all_records = 
            m_runtime->getAllRecords();
        
        if (!all_records.has_value()) {
            /**
             * @note Fail here because it means that the runtime hasnt been initialised yet.
             */
            return std::unexpected(SyncError::RuntimeError);
        }

        /**
         * @brief Add all pending deletes to the result, since the body is deleted after a record
         *  is set and the above code only checks for plain vault ciphers instead of SyncRecords.
         *  (only if it doesnt exist already)
         */
        for (PendingChange change : all_records.value()) {
            if (change.type == ChangeType::Deleted) {
                std::vector<SyncRecord>::iterator iterator = std::find_if(
                    result.begin(),
                    result.end(),
                    [&](const SyncRecord& sync_record) {
                        return sync_record.uuid == change.entity.id;
                    }
                );

                if (iterator != result.end()) {
                    continue;
                }

                SyncRecord record;
                if (change.entity.type == EntityType::Item) {
                    record.item_type = SyncItem::Item;
                } else if (change.entity.type == EntityType::Folder) {
                    record.item_type = SyncItem::Folder;
                } else if (change.entity.type == EntityType::Attachment) {
                    record.item_type = SyncItem::Attachment;
                    record.parent_id = change.entity.parent_id;
                }
                record.uuid = change.entity.id;
                record.revision = utils::s_getTime(change.revision_date);
                record.state = SyncState::PendingDelete;
                record.raw = change.base;

                result.push_back(record);
            } else if (change.entity.type == EntityType::Attachment &&
                       change.type == ChangeType::Created) {
                /**
                 * @note Attachment Updates don't contain a base or revision_date, so attachment
                 *  updates must be handled via an item update. We don't need to worry abt
                 *  attachment updates or clean attachments since if an attachment is created or
                 *  deleted or modified online, then it will be marked as an item update.
                 */
                SyncRecord record;
                record.item_type = SyncItem::Attachment;
                record.uuid = change.entity.id;
                record.parent_id = change.entity.parent_id;
                record.revision = utils::s_getTime(change.revision_date);
                record.state = SyncState::CreatedOffline;
                record.raw = change.base;

                result.push_back(record);
            }
        }

        return result;
    }
    
    /**
     * @brief To get remote records, we must loop through all the ciphers and folders and create a
     *  sync record for each of them.
     */
    std::expected<std::vector<SyncRecord>, SyncError> BitwardenSync::fetchRemoteRecords() {
        std::expected<nlohmann::json, NetworkError> remote_vault = 
            m_network->getVault();
        
        if (!remote_vault.has_value() || !remote_vault.value().is_object() || 
            !remote_vault.value().contains("ciphers") || 
            !remote_vault.value()["ciphers"].is_array() ||
            !remote_vault.value().contains("folders") || 
            !remote_vault.value()["folders"].is_array()) {
            return std::unexpected(SyncError::NetworkError);
        }

        std::vector<SyncRecord> result;

        for (const nlohmann::json& cipher : remote_vault.value()["ciphers"]) {
            if (!cipher.contains("id") || !cipher["id"].is_string() ||
                !cipher.contains("revisionDate") || !cipher["revisionDate"].is_string()) {
                continue;
            }

            SyncRecord record;
            record.item_type = SyncItem::Item;
            record.uuid = cipher["id"];
            record.revision = utils::s_getTime(cipher["revisionDate"]);
            record.state = SyncState::Clean;
            record.raw = cipher;

            result.push_back(record);
        }

        for (const nlohmann::json& folder : remote_vault.value()["folders"]) {
            if (!folder.contains("id") || !folder["id"].is_string() ||
                !folder.contains("revisionDate") || !folder["revisionDate"].is_string()) {
                continue;
            }

            SyncRecord record;
            record.item_type = SyncItem::Folder;
            record.uuid = folder["id"];
            record.revision = utils::s_getTime(folder["revisionDate"]);
            record.state = SyncState::Clean;
            record.raw = folder;

            result.push_back(record);
        }

        return result;
    }
    
    std::expected<SyncActions, SyncError> BitwardenSync::planActions(const std::vector<SyncRecord>& local, 
        const std::vector<SyncRecord>& remote) {
        SyncActions actions;

        /**
         * @note We should remove the record if it was created partially or
         *  created, etc after everything succeeds because we can always find it later.
         */
        std::vector<SyncRecord> created_partially_online;
        std::vector<SyncRecord> clean_records;
        std::vector<ItemId> partial_ids;

        /**
         * @note We must store the clean records as well, because we need to compare them against
         *  the remote ones.
         */
        for (SyncRecord record : local) {
            if (record.item_type == SyncItem::Attachment &&
                record.state == SyncState::CreatedOffline) {
                actions.push_create.push_back(record);
            } else if (record.item_type == SyncItem::Attachment &&
                record.state == SyncState::PendingDelete) {
                actions.push_delete.push_back(record);
            } else if (record.state == SyncState::CreatedOffline) {
                actions.push_create.push_back(record);
            } else if (record.state == SyncState::CreatedOfflinePartially) {
                bool created_remote = false;

                for (SyncRecord remote_record : remote) {
                    if (!remote_record.raw.contains("key") || !record.raw.contains("key")) {
                        continue;
                    }

                    if (record.raw["key"].is_string() && remote_record.raw["key"].is_string()) {
                        if (record.raw["key"] == remote_record.raw["key"]) {
                            partial_ids.push_back(remote_record.uuid);
                            created_remote = true;
                            break;
                        }
                    } else if (!record.raw["key"].is_string() && !remote_record.raw["key"].is_string()) {
                        if (!record.raw.contains("name") || !remote_record.raw.contains("name") ||
                            !record.raw["name"].is_string() || !remote_record.raw["name"].is_string() ||
                            !record.raw.contains("notes") || !remote_record.raw.contains("notes") ||
                            !record.raw.contains("type") || !remote_record.raw.contains("type") ||
                            !record.raw["type"].is_number() || !remote_record.raw["type"].is_number()) {
                            continue;    
                        }

                        if (record.raw["name"] == remote_record.raw["name"] &&
                            record.raw["notes"] == remote_record.raw["notes"] &&
                            record.raw["type"] == remote_record.raw["type"]) {
                            partial_ids.push_back(remote_record.uuid);
                            created_remote = true;
                            break;
                        }
                    }
                }

                if (!created_remote) {
                    actions.push_create.push_back(record);
                }
            } else if (record.state == SyncState::Modified) {
                /**
                 * @note If a record with the same id is newer than the revisionDate thats in raw
                 *  (the revisionDate in raw is the original server sync date and the one in record
                 *  is the local revisionDate) then put it into a conflicts vector and resolve it.
                 */
                if (std::find_if(remote.begin(), remote.end(),
                        [&record](const SyncRecord &r) { 
                            return (r.uuid == record.uuid) && (r.item_type == record.item_type); 
                        }) == remote.end()) {
                    SyncConflict conflict;
                    conflict.type = ConflictType::RemoteDelete_LocalUpdate;
                    conflict.local = record;

                    actions.conflicts.push_back(conflict);
                } else {
                    actions.push_update.push_back(record);
                }
            } else if (record.state == SyncState::PendingDelete) {
                actions.push_delete.push_back(record);
            } else if (std::find_if(remote.begin(), remote.end(),
                        [&record](const SyncRecord &r) { 
                            return (r.uuid == record.uuid) && (r.item_type == record.item_type); 
                        }) == remote.end()) {
                actions.pull_delete.push_back(record);
            } else {
                clean_records.push_back(record);
            }
        }

        std::vector<SyncRecord> confirmed_create;

        for (SyncRecord record : remote) {
            if (std::find(partial_ids.begin(), partial_ids.end(), record.uuid) 
                != partial_ids.end()) {
                continue;
            }
            
            if (std::find_if(local.begin(), local.end(),
                        [&record](const SyncRecord& rec) { 
                            return (rec.uuid == record.uuid) && (rec.item_type == record.item_type); 
                        }) == local.end() &&
                std::find_if(actions.push_delete.begin(), actions.push_delete.end(),
                        [&record](const SyncRecord& rec) { 
                            return (rec.uuid == record.uuid) && (rec.item_type == record.item_type); 
                        }) == actions.push_delete.end()) {
                actions.pull_create.push_back(record);
            } else {
                for (SyncRecord local_record : local) {
                    if ((local_record.uuid != record.uuid) || 
                        (local_record.item_type != record.item_type)) {
                        continue;
                    }
                    
                    std::time_t remote_time = record.revision;
                    std::time_t local_time = 0;

                    if (local_record.state == SyncState::Clean) {
                        local_time = local_record.revision;
                    } else {
                        if (local_record.raw.contains("revisionDate") &&
                            local_record.raw["revisionDate"].is_string()) {
                            local_time = utils::s_getTime(local_record.raw["revisionDate"]);
                        }
                    }

                    /**
                     * @note Usually we would pass the local_record, however, this one is different
                     *  because we have to pull the remote one directly.
                     */
                    if ((remote_time > local_time) && local_record.state == SyncState::Clean) {
                        actions.pull_update.push_back(record);
                    } else if ((remote_time > local_time) && local_record.state == SyncState::Modified) {
                        SyncConflict conflict;
                        conflict.type = ConflictType::BothEdited;
                        conflict.local = local_record;
                        conflict.remote = record;

                        actions.conflicts.push_back(conflict);

                        std::erase_if(actions.push_update, [&record](const SyncRecord &rec) {
                            return (rec.uuid == record.uuid) && (rec.item_type == record.item_type);
                        });
                    } else if ((remote_time > local_time) && local_record.state == SyncState::PendingDelete) {
                        SyncConflict conflict;
                        conflict.type = ConflictType::LocalDelete_RemoteUpdate;
                        conflict.local = local_record;
                        conflict.remote = record;

                        actions.conflicts.push_back(conflict);
                        
                        std::erase_if(actions.push_delete, [&record](const SyncRecord &rec) {
                            return (rec.uuid == record.uuid) && (rec.item_type == record.item_type);
                        });
                    }

                    break;
                }
            }
        }

        return actions;
    }
    
    std::expected<PushActions, SyncError> BitwardenSync::pushRemote(const SyncActions& actions) {
        PushActions result;

        for (SyncRecord record : actions.push_create) {
            if (!record.raw.contains("id") || !record.raw["id"].is_string()) {
                result.failed.push_back(record);
                continue;
            }

            nlohmann::json push_create_json = record.raw;

            if (record.item_type == SyncItem::Attachment) {
                push_create_json["lastKnownRevisionDate"] = push_create_json["revisionDate"];
                push_create_json.erase("url");
                push_create_json.erase("revisionDate");
                push_create_json.erase("createdOffline");
            }

            push_create_json.erase("id");

            std::expected<nlohmann::json, NetworkError> res;
                
            if (record.item_type == SyncItem::Item) {
                res = m_network->newItem(push_create_json);
            } else if (record.item_type == SyncItem::Folder) {
                if (!push_create_json.contains("name") || 
                    !push_create_json["name"].is_string()) {
                    result.failed.push_back(record);
                    continue;
                }

                res = m_network->createFolder(utils::getSecureVector(push_create_json["name"]));
            } else if (record.item_type == SyncItem::Attachment) {
                if (!push_create_json.contains("name") || 
                    !push_create_json["name"].is_string() ||
                    !push_create_json.contains("url") || 
                    !push_create_json["url"].is_string() ||
                    !push_create_json.contains("key") || 
                    !push_create_json["key"].is_string()) {
                    result.failed.push_back(record);
                    continue;
                }

                std::expected<Botan::secure_vector<uint8_t>, StorageError> attachment_err =
                    m_storage->read(record.raw["url"], [](float) {});
                
                if (!attachment_err.has_value()) {
                    result.failed.push_back(record);
                    continue;
                }

                res = m_network->addAttachment(record.parent_id, 
                    utils::getSecureVector(push_create_json["name"]), attachment_err.value(),
                    utils::getSecureVector(push_create_json["key"]), [](float) {});
            }

            if (!res.has_value()) {
                switch (res.error()) {
                    case NetworkError::Unreachable:
                    case NetworkError::Unauthorised:
                    case NetworkError::Forbidden:
                    case NetworkError::RateLimited:
                        result.failed.push_back(record);
                        break;
                    default:
                        result.partial.push_back(record);
                        break;
                }
            } else {
                if ((record.item_type != SyncItem::Attachment) && 
                    (!res.value().contains("id") || !res.value()["id"].is_string())) {
                    result.failed.push_back(record);
                    continue;
                }

                if ((record.item_type == SyncItem::Attachment) && 
                    (!res.value().contains("attachmentId") || !res.value()["attachmentId"].is_string())) {
                    result.failed.push_back(record);
                    continue;
                }

                SyncRecord success_record = record;
                success_record.raw = res.value();

                result.success.push_back(success_record);
                result.remap_id.push_back(std::make_pair(record.uuid, 
                    (record.item_type != SyncItem::Attachment) ? 
                        res.value()["id"] : res.value()["attachmentId"]));
            }
        }

        for (SyncRecord record : actions.push_update) {
            /**
             * @note Attachments should not have a push_update, instead, they should be updated via
             *  the item update.
             */
            if (record.item_type == SyncItem::Attachment) {
                continue;
            }

            nlohmann::json push_create_json = record.raw;

            push_create_json.erase("id");

            std::expected<nlohmann::json, NetworkError> res;
                
            if (record.item_type == SyncItem::Item) {
                res = m_network->updateItem(record.uuid, push_create_json);
            } else if (record.item_type == SyncItem::Folder) {
                if (!push_create_json.contains("name") || 
                    !push_create_json["name"].is_string()) {
                    result.failed.push_back(record);
                    continue;
                }

                res = m_network->renameFolder(record.uuid, utils::getSecureVector(push_create_json["name"]));
            }

            if (res.has_value()) {
                SyncRecord success_record = record;
                success_record.raw = res.value();

                result.success.push_back(success_record);
            } else {
                result.failed.push_back(record);
            }
        }
    }
    
    std::expected<bool, SyncError> BitwardenSync::pushLocal(const PushActions& actions) {
        
    }
    
    std::expected<SyncActions, SyncError> BitwardenSync::resolveConflicts(const SyncActions& actions) {
        SyncActions result = actions;

        std::erase_if(result.conflicts, [&](const SyncConflict& conflict) {
            if (conflict.type == ConflictType::LocalDelete_RemoteUpdate) {
                result.push_delete.push_back(conflict.local);
                return true;
            } else if (conflict.type == ConflictType::RemoteDelete_LocalUpdate) {
                result.pull_delete.push_back(conflict.local);
                return true;
            } else if (conflict.type == ConflictType::BothEdited) {
                /**
                 * @note We need to first compare the edited and original item and then get the 
                 *  parts changed. If the remote is older than the edited, then we can apply remote 
                 *  changes and then edited changes or if the edited is older than the remote, then
                 *  we can apply the remote changes onto the edited.
                 */
                if (!conflict.remote.has_value()) {
                    return false;
                }

                if (!conflict.local.raw.contains("revisionDate") || 
                    !conflict.local.raw["revisionDate"].is_string() ||
                    !conflict.remote.value().raw.contains("revisionDate") || 
                    !conflict.remote.value().raw["revisionDate"].is_string()) {
                    return false;
                }

                std::time_t local_revision = utils::s_getTime(conflict.local.raw["revisionDate"]);
                std::time_t remote_revision = utils::s_getTime(conflict.remote.value().raw["revisionDate"]);

                nlohmann::json resolved_json = nlohmann::json::object();
                
                Entity entity;
                entity.type = (conflict.local.item_type == SyncItem::Item) ? EntityType::Item : EntityType::Folder;
                entity.id = conflict.local.uuid;

                std::expected<PendingChange, RuntimeError> base_record = 
                    m_runtime->getRecord(entity);
                
                if (!base_record.has_value()) {
                    return false;
                }
                
                if (remote_revision > local_revision) {
                    resolved_json = mergeValues_(conflict.local.raw, 
                        conflict.remote.value().raw, false);
                } else {
                    resolved_json = mergeValues_(base_record.value().base, conflict.local.raw, 
                        conflict.remote.value().raw, true);
                }

                if (conflict.remote.value().raw.contains("attachments")) {
                    resolved_json["attachments"] = conflict.remote.value().raw["attachments"];
                } else {
                    /**
                     * @note We can safely erase this because it wont touch the vault and we have a
                     *  record that handles the offline creation and deletion of attachments anyway
                     */
                    resolved_json.erase("attachments");
                }

                SyncRecord record = conflict.local;
                record.state = SyncState::Modified;
                record.revision = utils::s_getTime(utils::s_getCurrentTime());
                record.raw = resolved_json;

                result.push_update.push_back(record);
                result.pull_update.push_back(record);

                return true;
            }

            return false;
        });

        return result;
    }
    
    nlohmann::json BitwardenSync::mergeValues_(nlohmann::json value_1, nlohmann::json value_2, 
        bool on_conflict) {
        if (value_1 == value_2) {
            return value_1;
        }

        /**
         * @brief Since both are objects, we can compare and merge by key
         */
        if (value_1.is_object() && value_2.is_object()) {
            std::set<std::string> keys;
            for (nlohmann::json value : { value_1, value_2 }) {
                for (nlohmann::json::const_iterator iterator = value.begin(); 
                    iterator != value.end(); ++iterator) {
                    keys.insert(iterator.key());
                }
            }

            nlohmann::json result = nlohmann::json::object();

            for (std::string key : keys) {
                nlohmann::json::const_iterator iterator_value_1 = value_1.find(key);
                nlohmann::json::const_iterator iterator_value_2 = value_2.find(key);

                if (iterator_value_1 == value_1.end())  {
                    result[key] = iterator_value_2.value();
                } else if (iterator_value_2 == value_2.end()) {
                    result[key] = iterator_value_1.value();
                } else {
                    result[key] = mergeValues_(iterator_value_1.value(), iterator_value_2.value(), 
                        on_conflict);
                }
            }

            return result;
        }

        return on_conflict ? value_1 : value_2;
    }

    nlohmann::json BitwardenSync::mergeValues_(nlohmann::json base, nlohmann::json value_1, 
        nlohmann::json value_2, bool on_conflict) {
        if (value_1 == value_2) {
            return value_1;
        }

        if (value_1 == base) {
            return value_2;
        }

        if (value_2 == base) {
            return value_1;
        }

        /**
         * @brief Since both are objects, we can compare and merge by key
         *  Had to use claude to help me with this
         */
        if (base.is_object() && value_1.is_object() && value_2.is_object()) {
            std::set<std::string> keys;
            for (nlohmann::json value : { base, value_1, value_2 }) {
                for (nlohmann::json::const_iterator iterator = value.begin(); 
                    iterator != value.end(); ++iterator) {
                    keys.insert(iterator.key());
                }
            }

            nlohmann::json result = nlohmann::json::object();

            for (std::string key : keys) {
                nlohmann::json::const_iterator iterator_base = base.find(key);
                nlohmann::json::const_iterator iterator_value_1 = value_1.find(key);
                nlohmann::json::const_iterator iterator_value_2 = value_2.find(key);

                bool in_base = (iterator_base != base.end());
                bool in_value_1 = (iterator_value_1 != value_1.end());
                bool in_value_2 = (iterator_value_2 != value_2.end());

                if (!in_value_1 && !in_value_2) {
                    /**
                     * @note nothing
                     */
                } else if (!in_value_1) {
                    if (!in_base) {
                        result[key] = iterator_value_2.value();
                    } else if (iterator_value_2.value() == iterator_base.value()) {
                        /**
                         * @note nothing
                         */
                    } else {
                        if (!on_conflict) {
                            result[key] = iterator_value_2.value();
                        }
                    }
                } else if (!in_value_2) {
                    if (!in_base) {
                        result[key] = iterator_value_1.value();
                    } else if (iterator_value_1.value() == iterator_base.value()) {
                        /**
                         * @note nothing
                         */
                    } else {
                        if (on_conflict) {
                            result[key] = iterator_value_1.value();
                        }
                    }
                } else {
                    if (in_base) {
                        result[key] = mergeValues_(iterator_base.value(), iterator_value_1.value(),
                            iterator_value_2.value(), on_conflict);
                    } else {
                        result[key] = mergeValues_(nlohmann::json::object(), iterator_value_1.value(),
                            iterator_value_2.value(), on_conflict);
                    }
                }
            }

            return result;
        }

        return on_conflict ? value_1 : value_2;
    }
}