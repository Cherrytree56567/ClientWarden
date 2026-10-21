#include "bitwarden_sync.h"

namespace clientwarden::vendor::bitwarden::vault {
    BitwardenSync::BitwardenSync(std::shared_ptr<Runtime> runtime, std::shared_ptr<Network> network, 
        std::shared_ptr<Settings> settings) : Sync(runtime, network, settings) {
        m_sync_thread.setCallback([this](const std::atomic<bool>& should_thread) {
            return syncCallback(should_thread);
        });
    }

    /**
     * @brief First, we must get the vault from the network and manually save it to the vault.json.
     * @note The caller of fullSync should also use loadVaultData in m_runtime.
     */
    std::expected<bool, SyncError> BitwardenSync::fullSync() {
        std::expected<nlohmann::json, NetworkError> vault_err = 
            m_network->getVault();
        
        if (!vault_err.has_value()) {
            return std::unexpected(SyncError::NetworkError);
        }

        if (!m_storage->write("vault.json", vault_err.value().dump(4)).has_value()) {
            return std::unexpected(RuntimeError::StorageFailure);
        }

        return true;
    }
    
    std::expected<bool, SyncError> BitwardenSync::startSyncThread() {
        m_sync_thread.start();

        return true;
    }
    
    std::expected<bool, SyncError> BitwardenSync::stopSyncThread() {
        m_sync_thread.stop();
        
        return true;
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

        /**
         * @brief First, we must get all the item and folder ids.
         */
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

        /**
         * @brief Then we can loop through all the types and ids.
         */
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
                    
                    if (pending_record.has_value()) {
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
                    } else if (pending_record.error() == RuntimeError::Uninitialised) {
                        return std::unexpected(SyncError::RuntimeError);
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
                } else {
                    continue;
                }

                record.uuid = change.entity.id;
                record.revision = utils::s_getTime(change.revision_date);
                record.state = SyncState::PendingDelete;
                record.raw = change.base;

                result.push_back(record);
            } else if (change.entity.type == EntityType::Attachment &&
                       (change.type == ChangeType::Created ||
                        change.type == ChangeType::CreatedPartial)) {
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
                record.state = (change.type == ChangeType::Created) ? SyncState::CreatedOffline :
                    SyncState::CreatedOfflinePartially;
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
    
    /**
     * @brief Determines what actions to take as part of the sync (eg: determining if an item was
     *  created online or failed, what items should be deleted, etc).
     */
    std::expected<SyncActions, SyncError> BitwardenSync::planActions(const std::vector<SyncRecord>& local, 
        const std::vector<SyncRecord>& remote) {
        SyncActions actions;

        /**
         * @note We should remove the record if it was created partially or
         *  created, etc after everything succeeds because we can always find it later.
         */
        std::vector<SyncRecord> clean_records;
        std::vector<ItemId> partial_ids;

        /**
         * @brief First, we need to push all records created offline to push_create.
         * @note We must store the clean records as well, because we need to compare them against
         *  the remote ones.
         */
        for (SyncRecord record : local) {
            if (record.state == SyncState::CreatedOffline) {
                actions.push_create.push_back(record);
            } else if (record.state == SyncState::CreatedOfflinePartially) {
                bool created_remote = false;

                /**
                 * @brief Check if the record was created online.
                 * @note We need to handle item, folder and attachment separately.
                 * @note If it was created partially then we should remove the record in pushLocal.
                 * @note Attachment doesnt use Created Partial
                 * @note We need to check the key, name, notes and type or just the name for item,
                 *  and check name for folder.
                 */
                for (SyncRecord remote_record : remote) {
                    /**
                     * @brief Ensure that the records have the same item types and aren't claimed
                     *  by another record.
                     */
                    if (remote_record.item_type != record.item_type) {
                        continue;
                    }

                    if (std::find(partial_ids.begin(), partial_ids.end(), remote_record.uuid)
                        != partial_ids.end()) {
                        continue;
                    }
                    
                    /**
                     * @brief Skips records that already exist on the remote and runtime.
                     */
                    if (std::find_if(local.begin(), local.end(), 
                        [&remote_record](const SyncRecord& loc) {
                            return loc.uuid == remote_record.uuid && loc.item_type == remote_record.item_type;
                        }) != local.end()) {
                        continue;
                    }

                    if (record.item_type == SyncItem::Item) {
                        if (remote_record.raw.contains("key") && record.raw.contains("key") &&
                            record.raw["key"].is_string() && remote_record.raw["key"].is_string()) {
                            if (record.raw["key"] == remote_record.raw["key"]) {
                                actions.pull_partial.push_back(std::make_pair(record, remote_record));
                                partial_ids.push_back(remote_record.uuid);
                                created_remote = true;
                                break;
                            }
                        } else if ((!remote_record.raw.contains("key") || !remote_record.raw["key"].is_string()) &&
                                (!record.raw.contains("key") || !record.raw["key"].is_string())) {
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
                                actions.pull_partial.push_back(std::make_pair(record, remote_record));
                                partial_ids.push_back(remote_record.uuid);
                                created_remote = true;
                                break;
                            }
                        }
                    } else if (record.item_type == SyncItem::Folder) {
                        if (!remote_record.raw.contains("name") || !record.raw.contains("name")) {
                            continue;
                        }

                        if (record.raw["name"].is_string() && remote_record.raw["name"].is_string()) {
                            if (record.raw["name"] == remote_record.raw["name"]) {
                                actions.pull_partial.push_back(std::make_pair(record, remote_record));
                                partial_ids.push_back(remote_record.uuid);
                                created_remote = true;
                                break;
                            }
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
        result.actions = actions;

        std::unordered_map<std::string, std::string> folder_ids;

        /**
         * @brief Sort the Folders first, to allow for remapping folder ids in items.
         */
        std::stable_sort(result.actions.push_create.begin(), result.actions.push_create.end(),
            [](const SyncRecord& a, const SyncRecord& b) {
                int rank_a =
                    a.item_type == SyncItem::Folder ? 0 :
                    a.item_type == SyncItem::Item ? 1 :
                    a.item_type == SyncItem::Attachment ? 2 : 3;

                int rank_b =
                    b.item_type == SyncItem::Folder ? 0 :
                    b.item_type == SyncItem::Item ? 1 :
                    b.item_type == SyncItem::Attachment ? 2 : 3;

                return rank_a < rank_b;
            });

        for (SyncRecord record : result.actions.push_create) {
            if (!record.raw.contains("id") || !record.raw["id"].is_string()) {
                result.failed.push_back(record);
                continue;
            } 

            nlohmann::json push_create_json = record.raw;

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
                if (!push_create_json.contains("fileName") || 
                    !push_create_json["fileName"].is_string() ||
                    !record.raw.contains("url") || 
                    !record.raw["url"].is_string() ||
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
                    utils::getSecureVector(push_create_json["fileName"]), attachment_err.value(),
                    utils::getSecureVector(push_create_json["key"]), [](float) {});
                
                Botan::secure_scrub_memory(attachment_err.value().data(), 
                    attachment_err.value().size());
            } else {
                result.failed.push_back(record);
                continue;
            }

            if (!res.has_value()) {
                switch (res.error()) {
                    case NetworkError::Unreachable:
                    case NetworkError::Unauthorised:
                    case NetworkError::Forbidden:
                    case NetworkError::RateLimited:
                    case NetworkError::NotFound:
                    case NetworkError::BadRequest:
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

                if (record.item_type == SyncItem::Folder) {
                    folder_ids[record.uuid] = res.value()["id"];
                }

                SyncRecord success_record = record;
                success_record.raw = res.value();

                result.success.push_back(success_record);
                result.remap_id.push_back(std::make_pair(record.uuid, 
                    (record.item_type != SyncItem::Attachment) ? 
                        res.value()["id"] : res.value()["attachmentId"]));
            }

            if (record.item_type == SyncItem::Item) {
                if (record.raw.contains("archivedDate") && 
                    record.raw["archivedDate"].is_string()) {
                    /**
                     * @brief Archive Item.
                     * @note We dont need to create a record, since orchestrator does it for us.
                     */
                    OrchestratorError archive_err = m_orchestrator->archiveItem(record.uuid);
                }

                if (record.raw.contains("deletedDate") && 
                    record.raw["deletedDate"].is_string()) {
                    /**
                     * @brief Soft Delete Item.
                     * @note We dont need to create a record, since orchestrator does it for us.
                     */
                    OrchestratorError soft_del_err = m_orchestrator->softDeleteItem(record.uuid);
                }
            }
        }

        for (SyncRecord record : result.actions.push_update) {
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

            /**
             * @brief Remove attachments that aren't already on the server, since  they will be
             *  uploaded anyway later.
             */
            if (push_create_json.contains("attachments") && push_create_json["attachments"].is_array()) {
                nlohmann::json used_attachments = nlohmann::json::array();

                for (nlohmann::json attachment : push_create_json["attachments"]) {
                    if (!(attachment.is_object() &&
                        attachment.contains("createdOffline") &&
                        attachment["createdOffline"].is_boolean() &&
                        attachment["createdOffline"].get<bool>())) {
                        used_attachments.push_back(attachment);
                    }
                }

                payload["attachments"] = used_attachments;
            }

            /**
             * @brief Use Server's folderid, and if it doesnt exist, fail.
             * @note This requires folder's to be sorted first.
             */
            if (payload.contains("folderId") && payload["folderId"].is_string()) {
                for (std::pair<const std::string, std::string> fold_id : folder_ids) {
                    if (fold_id.first == payload["folderId"]) {
                        payload["folderId"] = fold_id.second;
                        break;
                    }
                }
            }
            
            if (record.item_type == SyncItem::Item) {
                res = m_network->updateItem(record.uuid, push_create_json);
            } else if (record.item_type == SyncItem::Folder) {
                if (!push_create_json.contains("name") || 
                    !push_create_json["name"].is_string()) {
                    result.failed.push_back(record);
                    continue;
                }

                res = m_network->renameFolder(record.uuid, utils::getSecureVector(push_create_json["name"]));
            } else {
                result.failed.push_back(record);
                continue;
            }

            if (res.has_value()) {
                SyncRecord success_record = record;
                success_record.raw = res.value();

                result.success.push_back(success_record);
            } else {
                result.failed.push_back(record);
            }

            if (record.item_type == SyncItem::Item) {
                Entity entity;
                entity.type = EntityType::Item;
                entity.id = record.uuid;

                std::expected<PendingChange, RuntimeError> base_record = 
                    m_runtime->getRecord(entity);
                
                if (!base_record.has_value()) {
                    result.failed.push_back(record);
                    continue;
                } 

                if (base_record.value().type != ChangeType::Updated) {
                    result.failed.push_back(record);
                    continue;
                }

                /**
                 * @brief Check if it contained an archiveDate, and if it didn't and it contains one
                 *  now, then archive it.
                 */
                if ((!base_record.value().base.contains("archivedDate") ||
                    base_record.value().base["archivedDate"].is_null()) &&
                    record.raw.contains("archivedDate") &&
                    record.raw["archivedDate"].is_string()) {
                    /**
                     * @brief Archive Item.
                     * @note We dont need to create a record, since orchestrator does it for us.
                     */
                    OrchestratorError archive_err = m_orchestrator->archiveItem(record.uuid);
                }

                if ((!base_record.value().base.contains("deletedDate") ||
                    base_record.value().base["deletedDate"].is_null()) &&
                    record.raw.contains("deletedDate") &&
                    record.raw["deletedDate"].is_string()) {
                    /**
                     * @brief Soft Delete Item.
                     * @note We dont need to create a record, since orchestrator does it for us.
                     */
                    OrchestratorError soft_del_err = m_orchestrator->softDeleteItem(record.uuid);
                }
            }
        }

        for (SyncRecord record : result.actions.push_delete) {
            std::expected<nlohmann::json, NetworkError> res;
                
            if (record.item_type == SyncItem::Item) {
                res = m_network->deleteItem(record.uuid);
            } else if (record.item_type == SyncItem::Folder) {
                res = m_network->deleteFolder(record.uuid);
            } else if (record.item_type == SyncItem::Attachment) {
                res = m_network->removeAttachment(record.parent_id, 
                    utils::getSecureVector(record.uuid));
            } else {
                result.failed.push_back(record);
                continue;
            }

            if (!res.has_value() && res.error() != NetworkError::NotFound) {
                result.failed.push_back(record);
            } else {
                result.success.push_back(record);
            }
        }

        return result;
    }
    
    std::expected<bool, SyncError> BitwardenSync::pushLocal(const PushActions& push_actions) {
        PushActions actions = push_actions;

        for (SyncRecord record : push_actions.success) {
            Entity entity;
            
            if (record.item_type == SyncItem::Item) {
                entity.type = EntityType::Item;
            } else if (record.item_type == SyncItem::Folder) {
                entity.type = EntityType::Folder;
            } else if (record.item_type == SyncItem::Attachment) {
                entity.type = EntityType::Attachment;
            } else {
                continue;
            }

            entity.id = record.uuid;
            entity.parent_id = record.parent_id;

            RuntimeError err = m_runtime->removeRecord(entity);

            if (err != RuntimeError::NotFound && err != RuntimeError::Success) {
                continue;
            }
        }

        for (SyncRecord record : push_actions.partial) {
            PendingChange change;
            
            if (record.item_type == SyncItem::Item) {
                change.entity.type = EntityType::Item;
            } else if (record.item_type == SyncItem::Folder) {
                change.entity.type = EntityType::Folder;
            } else if (record.item_type == SyncItem::Attachment) {
                change.entity.type = EntityType::Attachment;
                change.base = record.raw;
            } else {
                continue;
            }

            change.entity.id = record.uuid;
            change.entity.parent_id = record.parent_id;
            change.type = ChangeType::CreatedPartial;

            if (record.raw.contains("revisionDate") && record.raw["revisionDate"].is_string()) {
                change.revision_date = record.raw["revisionDate"];
            }

            RuntimeError err = m_runtime->record(change);

            if (err != RuntimeError::Success) {
                continue;
            }
        }

        for (SyncRecord record : actions.actions.pull_create) {
            RuntimeError res;
                
            if (record.item_type == SyncItem::Item) {
                res = m_runtime->addItem(record.raw);
            } else if (record.item_type == SyncItem::Folder) {
                res = m_runtime->addFolder(record.raw);
            } else if (record.item_type == SyncItem::Attachment) {
                res = m_runtime->addAttachment(record.parent_id, record.raw);
            } else {
                actions.failed.push_back(record);
                continue;
            }

            if (res != RuntimeError::Success) {
                actions.failed.push_back(record);
            } else {
                actions.success.push_back(record);
            }
        }

        for (SyncRecord record : actions.actions.pull_update) {
            RuntimeError res;
                
            if (record.item_type == SyncItem::Item) {
                res = m_runtime->updateItem(record.uuid, record.raw);
            } else if (record.item_type == SyncItem::Folder) {
                res = m_runtime->updateFolder(record.uuid, record.raw);
            } else if (record.item_type == SyncItem::Attachment) {
                res = m_runtime->updateAttachment(record.parent_id, record.uuid, record.raw);
            } else {
                actions.failed.push_back(record);
                continue;
            }

            if (res != RuntimeError::Success) {
                actions.failed.push_back(record);
            } else {
                actions.success.push_back(record);
            }
        }

        for (SyncRecord record : actions.actions.pull_delete) {
            RuntimeError res;
                
            if (record.item_type == SyncItem::Item) {
                res = m_runtime->removeItem(record.uuid);
            } else if (record.item_type == SyncItem::Folder) {
                res = m_runtime->removeFolder(record.uuid);
            } else if (record.item_type == SyncItem::Attachment) {
                res = m_runtime->removeAttachment(record.parent_id, record.uuid);
            } else {
                actions.failed.push_back(record);
                continue;
            }

            if (res != RuntimeError::Success && res != RuntimeError::NotFound) {
                actions.failed.push_back(record);
            } else {
                actions.success.push_back(record);
            }
        }

        return true;
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
                
                resolved_json = mergeValues_(base_record.value().base, conflict.local.raw, 
                    conflict.remote.value().raw, !(remote_revision > local_revision));

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

    bool BitwardenSync::syncCallback(const std::atomic<bool>& should_thread) {
        int sync_delay = m_settings->getSyncDelay();

        while (should_thread) {
            syncVault();
                
            std::chrono::steady_clock::time_point deadline =
                std::chrono::steady_clock::now() + std::chrono::seconds(sync_delay);

            while (should_thread && std::chrono::steady_clock::now() < deadline) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }

        return true;
    }
}