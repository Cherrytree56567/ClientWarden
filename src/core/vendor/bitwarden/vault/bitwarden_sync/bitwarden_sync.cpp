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
                        record.state = SyncState::Updated;
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
         * @todo We need to figure out a place to remove the record if it was created partially or
         *  created, etc.
         */

        std::vector<SyncRecord> created_partially;
        std::vector<SyncRecord> clean_records;

        /**
         * @note We must store the clean records as well, because we need to compare them against
         *  the remote ones.
         */
        for (SyncRecord record : local) {
            if (record.state == SyncState::CreatedOffline) {
                actions.push_create.push_back(record);
            } else if (record.state == SyncState::CreatedOfflinePartially) {
                /**
                 * @note We need to put this into a diff record to compare with the remote.
                 */
                created_partially.push_back(record);
            } else if (record.state == SyncState::Updated) {
                /**
                 * @note If a record with the same id is newer than the revisionDate thats in raw
                 *  (the revisionDate in raw is the original server sync date and the one in record
                 *  is the local revisionDate) then put it into a conflicts vector and resolve it.
                 */
                actions.push_update.push_back(record);
            } else if (record.state == SyncState::PendingDelete) {
                actions.push_delete.push_back(record);
            } else if (std::find(remote.begin(), remote.end(), record) == remote.end()) {
                actions.pull_delete.push_back(record);
            } else {
                clean_records.push_back(record);
            }
        }

        for (SyncRecord record : remote) {

        }
    }
    
    std::expected<PushActions, SyncError> BitwardenSync::pushRemote(const SyncActions& actions) {
        
    }
    
    std::expected<bool, SyncError> BitwardenSync::pushLocal(const PushActions& actions) {
        
    }
    
    std::expected<SyncActions, SyncError> BitwardenSync::resolveConflicts(const SyncActions& actions) {
        
    }
}