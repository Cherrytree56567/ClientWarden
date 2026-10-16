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
     * @todo Add Attachments in this too
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
            m_runtime->getAllRecords(C);
        
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
                record.item_type = SyncItem::Item;
                record.uuid = change.entity.id;
                record.revision = utils::s_getTime(change.revision_date);
                record.state = SyncState::PendingDelete;
                record.raw = change.base;

                result.push_back(record);
            } else if (change.entity.type == EntityType::Attachment) {
                /**
                 * @note Attachment Updates don't contain a base or revision_date, so attachment
                 *  updates must be handled via an item update.
                 */
                SyncRecord record;
                record.item_type = SyncItem::Attachmnet;
                record.uuid = change.entity.id;
                record.revision = utils::s_getTime(change.revision_date);
                record.state = SyncState::PendingDelete;
                record.raw = change.base;

                result.push_back(record);
            }
        }

        return result;
    }
    
    std::expected<std::vector<SyncRecord>, SyncError> BitwardenSync::fetchRemoteRecords() {
        std::expected<nlohmann::json, NetworkError> remote_vault = 
            m_network->getVault();
        
        if (!remote_vault.has_value() || !remote_vault.value().is_object() || 
            !remote_vault.value().contains("ciphers") || 
            !remote_vault.value()["ciphers"].is_array()) {
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
            if (record.state == SyncState::CreatedOffline) {
                actions.push_create.push_back(record);
            } else if (record.state == SyncState::CreatedOfflinePartially) {
                bool created_remote = false;

                for (SyncRecord remote_record : remote) {
                    if (!remote_record.raw.contains("key") || !record.raw.contains("key")) {
                        continue;
                    }

                    if (record.raw["key"].is_string() && remote_record.raw["key"].is_string()) {
                        if (record.raw["key"] == remote_record.raw["key"]) {
                            partial_ids.push_back(remote_record.entity.id);
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
                            partial_ids.push_back(remote_record.entity.id);
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
                            return r.entity.id == record.entity.id; 
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
                            return r.entity.id == record.entity.id; 
                        }) == remote.end()) {
                actions.pull_delete.push_back(record);
            } else {
                clean_records.push_back(record);
            }
        }

        std::vector<SyncRecord> confirmed_create;

        for (SyncRecord record : remote) {
            if (std::find(partial_ids.begin(), partial_ids.end(), record.entity.id) 
                != partial_ids.end()) {
                continue;
            }
            
            if (std::find_if(local.begin(), local.end(),
                        [&record](const SyncRecord& rec) { 
                            return rec.entity.id == record.entity.id; 
                        }) == local.end() &&
                std::find_if(actions.push_delete.begin(), actions.push_delete.end(),
                        [&record](const SyncRecord& rec) { 
                            return rec.entity.id == record.entity.id; 
                        }) == actions.push_delete.end()) {
                actions.pull_create.push_back(record);
            } else {
                for (SyncRecord local_record : local) {
                    if (local_record.entity.id != record.entity.id) {
                        continue;
                    }
                    
                    std::time_t remote_time = utils::s_getTime(record.revision_date);
                    std::time_t local_time = 0;

                    if (local_record.state == SyncState::Clean) {
                        local_time = utils::s_getTime(local_record.revision_date);
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
                            return rec.entity.id == record.entity.id;
                        });
                    } else if ((remote_time > local_time) && local_record.state == SyncState::PendingDelete) {
                        SyncConflict conflict;
                        conflict.type = ConflictType::LocalDelete_RemoteUpdate;
                        conflict.local = local_record;
                        conflict.remote = record;

                        actions.conflicts.push_back(conflict);
                        
                        std::erase_if(actions.push_delete, [&record](const SyncRecord &rec) {
                            return rec.entity.id == record.entity.id;
                        });
                    }

                    break;
                }
            }
        }

        return actions;
    }
    
    std::expected<PushActions, SyncError> BitwardenSync::pushRemote(const SyncActions& actions) {
        
    }
    
    std::expected<bool, SyncError> BitwardenSync::pushLocal(const PushActions& actions) {
        
    }
    
    /**
     * @todo This should also work for attachments
     */
    std::expected<SyncActions, SyncError> BitwardenSync::resolveConflicts(const SyncActions& actions) {
        SyncActions result = actions;

        std::erase_if(result.conflicts, [&](const SyncConflict& conflict) {
            if (conflict.type == ConflictType::LocalDelete_RemoteUpdate) {
                result.push_delete.push_back(conflict.local);
                return true;
            } else if (conflict.type == ConflictType::RemoteDelete_LocalUpdate) {
                result.pull_delete.push_back(conflict.remote);
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