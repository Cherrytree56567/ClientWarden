#include "bitwarden_orchestrator.h"

namespace clientwarden::vendor::bitwarden::vault {
    BitwardenOrchestrator::BitwardenOrchestrator(std::shared_ptr<Crypto> crypto, 
        std::shared_ptr<Network> network, std::shared_ptr<Runtime> runtime, 
        std::shared_ptr<Storage> storage) :
        Orchestrator(crypto, network, runtime, storage) {
        
    }

    /**
     * @brief To check if a session has been invalidated, we can compare the remote
     *  security stamp and the runtime security stamp.
     * @todo Handle Network errors where the network is unauth'd,
     */
    std::expected<bool, OrchestratorError> BitwardenOrchestrator::sessionInvalidated() {
        std::expected<Profile, NetworkError> network_profile = m_network->getProfile();
        if (!network_profile.has_value()) {
            return std::unexpected(OrchestratorError::NetworkError);
        }

        std::expected<Profile, RuntimeError> runtime_profile = m_runtime->getProfile();
        if (!runtime_profile.has_value()) {
            return std::unexpected(OrchestratorError::RuntimeError);
        }
        
        return runtime_profile.security_stamp != network_profile.security_stamp;
    }
    
    /**
     * @note Data still requires a temp id which is then replaced by the server's id.
     * @brief To create a new item, we must first create the item on the remote, and then
     *  if it fails, mark it as created offline. We can then add it to the runtime.
     * @note We dont need to worry if the network fails and if its on the remote or not, bc
     *  we can always compare it at sync time.
     * @note If an item failed to create online, then mark it as partially created, or created
     *  offline before pushing it to the vault.
     */
    std::expected<ItemId, OrchestratorError> BitwardenOrchestrator::newItem(nlohmann::json data) {
        if (!data.is_object()) {
            return std::unexpected(OrchestratorError::InvalidParams);
        }

        if (!data.contains("id") || !data["id"].is_string()) {
            return std::unexpected(OrchestratorError::InvalidParams);
        }

        nlohmann::json network_data = data;
        network_data.erase("id");

        std::expected<nlohmann::json, NetworkError> network_item = m_network->newItem(network_data);

        nlohmann::json result_data = data;
        bool created_offline = true;
        
        if (!network_item.has_value() && network_item.error() == NetworkError::Unauthorised) {
            if (m_network->refreshToken().has_value()) {
                network_item = m_network->newItem(network_data);
            }
        }

        if (network_item.has_value()) {
            created_offline = false;
            result_data = network_item.value();
        }

        if (!result_data.contains("id") || !result_data["id"].is_string()) {
            return std::unexpected(OrchestratorError::InvalidParams);
        }

        if (created_offline) {
            PendingChange change;
            change.entity.type = EntityType::Item;
            change.entity.id = result_data["id"];

            switch (network_item.error()) {
                case NetworkError::Unreachable:
                case NetworkError::Unauthorised:
                case NetworkError::Forbidden:
                case NetworkError::RateLimited:
                    change.type = ChangeType::Created;
                    break;
                case NetworkError::BadRequest:
                    return std::unexpected(OrchestratorError::InvalidParams);
                default:
                    change.type = ChangeType::CreatedPartial;
                    break;
            }

            RuntimeError err = m_runtime->record(change);
            if (err != RuntimeError::Success) {
                return std::unexpected(OrchestratorError::RuntimeError);
            }
        }

        RuntimeError runtime_item = m_runtime->addItem(result_data);
        if (runtime_item != RuntimeError::Success) {
            return std::unexpected(OrchestratorError::RuntimeError);
        }

        return result_data["id"];
    }
    
    /**
     * @brief To update the item, we first need to make a network_data version, since the bw server
     *  requires an encryptedFor value when updating. If the item was marked as created offline,
     *  then we must create it on the remote and if its successful, unmark it. If the item needs to
     *  be updated, then add an encryptedFor value with the original provided id value. Then we can
     *  add it to the runtime (local vault) and then mark it offline if needed.
     * @note If updating fails, we should record an offline update item before pushing it to the
     *  vault.
     */
    OrchestratorError BitwardenOrchestrator::updateItem(nlohmann::json data) {
        if (!data.is_object()) {
            return OrchestratorError::InvalidParams;
        }

        if (!data.contains("id") || !data["id"].is_string()) {
            return OrchestratorError::InvalidParams;
        }

        std::expected<nlohmann::json, RuntimeError> item_json = m_runtime->getItem(data["id"]);
        if (!item_json.has_value()) {
            return OrchestratorError::NotFound;
        }

        if (!m_profile_id_set_) {
            std::expected<Profile, RuntimeError> profile = m_runtime->getProfile();
            if (profile.has_value()) {
                m_profile_id_ = profile.value().id;
                m_profile_id_set_ = true;
            }
        }

        nlohmann::json network_data = data;
        network_data.erase("id");

        std::expected<nlohmann::json, NetworkError> network_item;

        Entity entity;
        entity.type = EntityType::Item;
        entity.id = data["id"];

        std::expected<bool, RuntimeError> is_created_offline = 
            m_runtime->recordExists(entity);

        if (is_created_offline.has_value() && is_created_offline.value()) {
            network_item = m_network->newItem(network_data);
        } else {
            network_data["encryptedFor"] = m_profile_id_;
            network_item = m_network->updateItem(data["id"], network_data);
        }

        nlohmann::json result_data = data;
        bool updated_offline = true;

        if (network_item.has_value()) {
            updated_offline = false;
            result_data = network_item.value();

            if (is_created_offline.has_value() && is_created_offline.value()) {
                m_runtime->removeRecord(entity);
            }
        }

        if (!result_data.contains("id") || !result_data["id"].is_string()) {
            return OrchestratorError::InvalidParams;
        }

        if (updated_offline) {
            PendingChange change;
            change.entity = entity;
            change.type = ChangeType::Updated;
            change.base = item_json.value();
            change.revision_date = utils::s_getCurrentTime();

            RuntimeError err = m_runtime->record(change);

            if (err != RuntimeError::Success && err != RuntimeError::ExistingItem) {
                return OrchestratorError::RuntimeError;
            }
        }

        RuntimeError runtime_item = m_runtime->updateItem(data["id"], result_data);
        if (runtime_item != RuntimeError::Success) {
            return OrchestratorError::RuntimeError;
        }

        return OrchestratorError::Success;
    }
    
    /**
     * @brief First, we can immediately unmark the item as created offline. Then, we can remove the
     *  item from the server and if it fails, mark it as deleted offline. After that, we can delete
     *  it locally.
     */
    OrchestratorError BitwardenOrchestrator::deleteItem(ItemId uuid) {
        Entity entity;
        entity.type = EntityType::Item;
        entity.id = uuid;

        std::expected<bool, RuntimeError> is_created_offline = 
            m_runtime->recordExists(entity);
        
        if (is_created_offline.has_value() && is_created_offline.value()) {
            m_runtime->removeRecord(entity);

            RuntimeError runtime_delete = m_runtime->removeItem(uuid);
            if (runtime_delete != RuntimeError::Success) {
                return OrchestratorError::RuntimeError;
            }
            
            return OrchestratorError::Success;
        }

        std::expected<nlohmann::json, NetworkError> network_delete = m_network->deleteItem(uuid);

        if (!network_delete.has_value()) {
            PendingChange change;
            change.entity = entity;
            change.type = ChangeType::Deleted;
            change.revision_date = utils::s_getCurrentTime();

            std::expected<nlohmann::json, RuntimeError> item_json = 
                m_runtime->getItem(uuid);
            
            if (!item_json.has_value()) {
                return OrchestratorError::RuntimeError;
            }

            change.base = item_json.value();

            m_runtime->record(change);
        }

        RuntimeError runtime_delete = m_runtime->removeItem(uuid);
        if (runtime_delete != RuntimeError::Success) {
            return OrchestratorError::RuntimeError;
        }

        return OrchestratorError::Success;
    }
    
    /**
     * @brief To soft delete the item, we must first aquire the cipher from the vault. Then, we can
     *  add the deletedDate to it and ask the server to softDelete it and then update the runtime
     *  with the deletedDate item.
     * @note If it was unsuccessful with the remote soft delete, then the sync should re-perform the
     *  soft delete if it contains a deletion date and has a higher revision date.
     * @note We dont need to check the result of the remote soft deletion because it will be re
     *  performed anyway by the sync, if unsuccessful.
     */
    OrchestratorError BitwardenOrchestrator::softDeleteItem(ItemId uuid) {
        std::expected<nlohmann::json, RuntimeError> item_res = m_runtime->getItem(uuid);
        if (!item_res.has_value()) {
            return OrchestratorError::NotFound;
        }

        nlohmann::json item = item_res.value();

        item["deletedDate"] = utils::s_getCurrentTime();

        std::expected<nlohmann::json, NetworkError> soft_delete_res = m_network->softDeleteItem(uuid);

        RuntimeError res = m_runtime->updateItem(uuid, item);

        if (res != RuntimeError::Success) {
            return OrchestratorError::RuntimeError;
        }

        return OrchestratorError::Success;
    }
    
    /**
     * @brief This is the same as softDeleteItem.
     */
    OrchestratorError BitwardenOrchestrator::restoreItem(ItemId uuid) {
        std::expected<nlohmann::json, RuntimeError> item_res = m_runtime->getItem(uuid);
        if (!item_res.has_value()) {
            return OrchestratorError::NotFound;
        }

        nlohmann::json item = item_res.value();

        item["deletedDate"] = nullptr;

        std::expected<nlohmann::json, NetworkError> restore_res = m_network->restoreItem(uuid);

        RuntimeError res = m_runtime->updateItem(uuid, item);

        if (res != RuntimeError::Success) {
            return OrchestratorError::RuntimeError;
        }

        return OrchestratorError::Success;
    }
    
    /**
     * @brief This is the same as softDeleteItem.
     */
    OrchestratorError BitwardenOrchestrator::archiveItem(ItemId uuid) {
        std::expected<nlohmann::json, RuntimeError> item_res = m_runtime->getItem(uuid);
        if (!item_res.has_value()) {
            return OrchestratorError::NotFound;
        }

        nlohmann::json item = item_res.value();

        item["archivedDate"] = utils::s_getCurrentTime();

        std::expected<nlohmann::json, NetworkError> archive_res = m_network->archiveItem(uuid);

        RuntimeError res = m_runtime->updateItem(uuid, item);

        if (res != RuntimeError::Success) {
            return OrchestratorError::RuntimeError;
        }

        return OrchestratorError::Success;
    }
    
    /**
     * @brief This is the same as softDeleteItem.
     */
    OrchestratorError BitwardenOrchestrator::unArchiveItem(ItemId uuid) {
        std::expected<nlohmann::json, RuntimeError> item_res = m_runtime->getItem(uuid);
        if (!item_res.has_value()) {
            return OrchestratorError::NotFound;
        }

        nlohmann::json item = item_res.value();

        item["archivedDate"] = nullptr;

        std::expected<nlohmann::json, NetworkError> archive_res = m_network->unArchiveItem(uuid);

        RuntimeError res = m_runtime->updateItem(uuid, item);

        if (res != RuntimeError::Success) {
            return OrchestratorError::RuntimeError;
        }

        return OrchestratorError::Success;
    }
    
    /**
     * @note If an attachment is created offline, or was partially created online, we always check 
     *  if it exists online and replace it.
     */
    std::expected<Botan::secure_vector<uint8_t>, OrchestratorError> BitwardenOrchestrator::addAttachment(
        ItemId uuid, Botan::secure_vector<uint8_t>& file_contents, 
        const Botan::secure_vector<uint8_t>& file_name, 
        std::function<void(float)> on_progress) {
        std::expected<ItemKey, CryptoErrors> attachment_key_res = m_crypto->generateKey();

        if (!attachment_key_res.has_value()) {
            return std::unexpected(OrchestratorError::CryptoError);
        }

        /**
         * @brief Get an encrypted Attachment Key
         */
        ItemKey attachment_key = std::move(attachment_key_res.value());

        Botan::secure_vector<uint8_t> str_attachment_key(attachment_key.enc_key.begin(), attachment_key.enc_key.end());
        str_attachment_key.insert(str_attachment_key.end(), attachment_key.mac_key.begin(), attachment_key.mac_key.end());

        std::expected<nlohmann::json, RuntimeError> item = m_runtime->getItem(uuid);

        if (!item.has_value()) {
            return std::unexpected(OrchestratorError::RuntimeError);
        }

        if (item.value().contains("key") && !item.value()["key"].is_null()) {
            std::expected<ItemKey, CryptoErrors> item_key_err = 
                m_crypto->resolveItemKey(utils::getSecureVector(item.value()["key"].get<std::string>()));

            if (!item_key_err.has_value()) {
                return std::unexpected(OrchestratorError::CryptoError);
            }

            std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> str_att_key_err = 
                m_crypto->encrypt(str_attachment_key, item_key_err.value());

            if (!str_att_key_err.has_value()) {
                return std::unexpected(OrchestratorError::CryptoError);
            }

            str_attachment_key = std::move(str_att_key_err.value());
        } else {
            std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> str_att_key_err = 
                m_crypto->encrypt(str_attachment_key);

            if (!str_att_key_err.has_value()) {
                return std::unexpected(OrchestratorError::CryptoError);
            }

            str_attachment_key = std::move(str_att_key_err.value());
        }

        /**
         * @brief Encrypt the File name
         */
        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> enc_res = 
            m_crypto->encrypt(file_name, attachment_key);
        
        if (!enc_res.has_value()) {
            return std::unexpected(OrchestratorError::CryptoError);
        }

        Botan::secure_vector<uint8_t> enc_file_name = std::move(enc_res.value());

        /**
         * @brief Make sure to encrypt the file contents in place since they can get up to 500mb.
         */
        CryptoErrors err = m_crypto->encryptBinaryInPlace(file_contents, attachment_key);

        if (err != CryptoErrors::Success) {
            return std::unexpected(OrchestratorError::CryptoError);
        }

        attachment_key.clear();

        std::expected<nlohmann::json, NetworkError> network_attachment = 
            m_network->addAttachment(uuid, enc_file_name, file_contents, str_attachment_key,
            on_progress);
        
        /**
         * @note If it is created offline, then the (encrypted) file_contents should be saved as
         *  the (encrypted) file_name + .enc in the attachments folder and be queued to sync.
         */
        if (!network_attachment.has_value()) {
            if (network_attachment.error() == NetworkError::Forbidden) {
                return std::unexpected(OrchestratorError::PremiumRequired);
            } else if (network_attachment.error() == NetworkError::NotFound) {
                return std::unexpected(OrchestratorError::NotFound);
            } else if (network_attachment.error() == NetworkError::BadRequest) {
                return std::unexpected(OrchestratorError::AttachmentTooLarge);
            } else {
                nlohmann::json attachment_json;
                attachment_json["adminRequest"] = false;
                attachment_json["fileName"] = utils::getString(enc_file_name);
                attachment_json["fileSize"] = file_contents.size();
                attachment_json["id"] = utils::getUniqueId();
                attachment_json["key"] = utils::getString(str_attachment_key);
                attachment_json["url"] = "attachments/" + attachment_json["id"];
                attachment_json["revisionDate"] = utils::getBitwardenTime();
                attachment_json["createdOffline"] = true;

                PendingChange change;
                change.entity.type = EntityType::Attachment;
                change.entity.id = attachment_json["id"];
                change.entity.parent_id = uuid;
                change.revision_date = utils::s_getCurrentTime();
                change.base = attachment_json;
                change.type = ChangeType::Created;

                RuntimeError mark_err = m_runtime->record(change);

                if (mark_err != RuntimeError::Success && mark_err != RuntimeError::ExistingItem) {
                    return std::unexpected(OrchestratorError::RuntimeError);
                }

                RuntimeError attachment_err = m_runtime->addAttachment(uuid, attachment_json);

                if (attachment_err != RuntimeError::Success && attachment_err != RuntimeError::ExistingItem) {
                    return std::unexpected(OrchestratorError::RuntimeError);
                }

                if (!m_storage->write("attachments/" + attachment_json["id"], file_contents)) {
                    return std::unexpected(OrchestratorError::StorageFailure);
                }

                return utils::getSecureVector(attachment_json["id"]);
            }
        } else {
            if (!network_attachment.value().contains("cipherResponse") || 
                !network_attachment.value()["cipherResponse"].is_object() ||
                !network_attachment.value().contains("attachmentId") ||
                !network_attachment.value()["attachmentId"].is_string()) {
                return std::unexpected(OrchestratorError::NetworkError);
            }

            RuntimeError runtime_attachment = m_runtime->updateItem(uuid, network_attachment.value()["cipherResponse"]);

            if (runtime_attachment != RuntimeError::Success) {
                return std::unexpected(OrchestratorError::RuntimeError);
            }

            return utils::getSecureVector(network_attachment.value()["attachmentId"]);
        }
    }
    
    /**
     * @brief To remove the attachment, we must first check if the attachment was created offline,
     *  if it was, remove it and return Success. If it was created online, then ask network and
     *  runtime to remove them from the remote and local vaults.
     */
    OrchestratorError BitwardenOrchestrator::removeAttachment(ItemId uuid, 
        const Botan::secure_vector<uint8_t> attachment_id) {
        ItemId id = utils::getString(attachment_id);

        Entity entity;
        entity.type = EntityType::Attachment;
        entity.id = id;
        entity.parent_id = uuid;

        if (!m_runtime->getAttachment(uuid, id).has_value()) {
            return OrchestratorError::NotFound;
        }

        std::expected<bool, RuntimeError> is_local = m_runtime->recordExists(entity);

        std::expected<nlohmann::json, NetworkError> net_err = 
            m_network->removeAttachment(uuid, attachment_id);
        
        bool deleted_offline = false;
        
        if (!net_err.has_value()) {
            switch (net_err.error()) {
                case NetworkError::NotFound:
                    break;
                case NetworkError::BadRequest:
                    return OrchestratorError::InvalidParams;
                default:
                    deleted_offline = true;
            }
        }

        if (deleted_offline || (is_local.has_value() && is_local.value())) {
            std::expected<nlohmann::json, RuntimeError> attachment_json = 
                m_runtime->getAttachment(uuid, attachment_id);
            
            if (!attachment_json.has_value()) {
                return OrchestratorError::RuntimeError;
            }

            PendingChange change;
            change.entity = entity;
            change.type = ChangeType::Deleted;
            change.revision_date = utils::s_getCurrentTime();
            change.base = attachment_json.value();

            RuntimeError err = m_runtime->record(change);

            if (err != RuntimeError::Success && err != RuntimeError::NotFound) {
                return OrchestratorError::RuntimeError;
            }
        } else {
            RuntimeError err = m_runtime->removeRecord(entity);

            if (err != RuntimeError::Success && err != RuntimeError::NotFound) {
                return OrchestratorError::RuntimeError;
            }
        }

        RuntimeError run_err = m_runtime->removeAttachment(uuid, attachment_id);

        if (run_err != RuntimeError::Success && run_err != RuntimeError::NotFound) {
            return OrchestratorError::RuntimeError;
        }

        m_storage->remove("attachments/" + id);

        return OrchestratorError::Success;
    }
    
    /**
     * @brief To download an attachment, (if offline) we can copy the attachment from the local
     *  pending attachments folder and copy it. If the attachment was pushed online, then we can
     *  use m_network to download it and save it to the filepath.
     */
    OrchestratorError BitwardenOrchestrator::downloadAttachment(ItemId uuid, 
        const Botan::secure_vector<uint8_t>& attachment_id, std::filesystem::path save_path,
        std::function<void(float)> on_progress) {
        Entity entity;
        entity.type = EntityType::Attachment;
        entity.id = utils::getString(attachment_id);
        entity.parent_id = uuid;

        /**
         * @brief Get the item key.
         */
        std::expected<bool, RuntimeError> is_local = m_runtime->recordExists(entity);

        std::expected<nlohmann::json, RuntimeError> item = m_runtime->getItem(uuid);

        if (!item.has_value() || !item.value().contains("key") || 
            !item.value()["key"].is_string()) {
            return OrchestratorError::RuntimeError;
        }

        Botan::secure_vector<uint8_t> botan_item_key = utils::getSecureVector(item.value()["key"]);

        std::expected<ItemKey, CryptoErrors> item_key = m_crypto->resolveItemKey(botan_item_key);

        Botan::secure_scrub_memory(botan_item_key.data(), botan_item_key.size());

        if (!item_key.has_value()) {
            return OrchestratorError::CryptoError;
        }

        /**
         * @brief Get the Attachment Data and Attachment JSON.
         */
        Botan::secure_vector<uint8_t> attachment_data;
        nlohmann::json attachment_json;

        if (is_local.has_value() && is_local.value()) {
            std::expected<nlohmann::json, RuntimeError> attachment_err = 
                m_runtime->getAttachment(uuid, attachment_id);
            
            if (!attachment_err.has_value()) {
                item_key.value().clear();
                return OrchestratorError::RuntimeError;
            }

            attachment_json = attachment_err.value();

            if (!attachment_json.contains("url") || !attachment_json["url"].is_string() ||
                !attachment_json.contains("createdOffline") || !attachment_json["createdOffline"].is_bool() ||
                !(attachment_json["createdOffline"].get<bool>())) {
                item_key.value().clear();
                return OrchestratorError::RuntimeError;
            }

            std::expected<Botan::secure_vector<uint8_t>, StorageError> attachment_storage_err = 
                m_storage->read("attachments/" + entity.id, on_progress, .9);
            
            if (!attachment_storage_err.has_value()) {
                item_key.value().clear();
                return OrchestratorError::StorageFailure;
            }
            
            attachment_data = std::move(attachment_storage_err.value());
        } else {
            std::expected<nlohmann::json, NetworkError> attachment_err = 
                m_network->downloadAttachment(uuid, attachment_id, on_progress, attachment_data);
            
            if (!attachment_err.has_value()) {
                item_key.value().clear();
                return OrchestratorError::NetworkError;
            }

            attachment_json = attachment_err.value();
        }
        
        /**
         * @brief Decrypt the File Name, Key and File Contents.
         */
        if (!attachment_json.contains("fileName") || !attachment_json["fileName"].is_string() ||
            !attachment_json.contains("key") || !attachment_json["key"].is_string()) {
            Botan::secure_scrub_memory(attachment_data.data(), attachment_data.size());
            item_key.value().clear();
            return OrchestratorError::RuntimeError;
        }

        Botan::secure_vector<uint8_t> file_name = utils::getSecureVector(attachment_json["fileName"]);
        Botan::secure_vector<uint8_t> key = utils::getSecureVector(attachment_json["key"]);

        std::expected<ItemKey, CryptoErrors> attachment_key = m_crypto->resolveItemKey(key, item_key.value());

        item_key.value().clear();
        
        Botan::secure_scrub_memory(key.data(), key.size());
        Botan::secure_scrub_memory(botan_item_key.data(), botan_item_key.size());

        if (!attachment_key.has_value()) {
            Botan::secure_scrub_memory(attachment_data.data(), attachment_data.size());
            return OrchestratorError::CryptoError;
        }

        on_progress(.92f);

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> dec_file_name = 
            m_crypto->decrypt(file_name, attachment_key.value());
        
        on_progress(.94f);

        if (!dec_file_name.has_value()) {
            Botan::secure_scrub_memory(attachment_data.data(), attachment_data.size());
            attachment_key.value().clear();
            return OrchestratorError::CryptoError;
        }

        file_name = std::move(dec_file_name.value());

        CryptoErrors contents_err = m_crypto->decryptBinaryInPlace(attachment_data, attachment_key.value());

        attachment_key.value().clear();

        on_progress(.96f);

        if (contents_err != CryptoErrors::Success) {
            Botan::secure_scrub_memory(attachment_data.data(), attachment_data.size());
            Botan::secure_scrub_memory(file_name.data(), file_name.size());
            
            return OrchestratorError::CryptoError;
        }

        if (!m_storage->write(save_path / utils::getString(file_name), attachment_data)) {
            Botan::secure_scrub_memory(attachment_data.data(), attachment_data.size());
            Botan::secure_scrub_memory(file_name.data(), file_name.size());

            return OrchestratorError::StorageFailure;
        }

        on_progress(1.0f);

        Botan::secure_scrub_memory(attachment_data.data(), attachment_data.size());
        Botan::secure_scrub_memory(file_name.data(), file_name.size());

        return OrchestratorError::Success;
    }
    
    std::expected<ItemId, OrchestratorError> BitwardenOrchestrator::createFolder(
        const Botan::secure_vector<uint8_t>& folder_name) {
        std::expected<nlohmann::json, NetworkError> network_err = 
            m_network->createFolder(folder_name);
        
        bool created_offline = true;
        nlohmann::json result;

        if (network_err.has_value()) {
            created_offline = false;
            result = network_err.value();
        } else {
            result["id"] = utils::getUniqueId();
            result["name"] = utils::getString(folder_name);
            result["object"] = "folder";
            result["revisionDate"] = utils::s_getCurrentTime();
        }

        if (created_offline) {
            PendingChange change;
            change.entity.type = EntityType::Folder;
            change.entity.id = result["id"];

            switch (network_err.error()) {
                case NetworkError::Unreachable:
                case NetworkError::Unauthorised:
                case NetworkError::Forbidden:
                case NetworkError::RateLimited:
                    change.type = ChangeType::Created;
                    break;
                case NetworkError::BadRequest:
                    return std::unexpected(OrchestratorError::InvalidParams);
                default:
                    change.type = ChangeType::CreatedPartial;
                    break;
            }

            RuntimeError err = m_runtime->record(change);
            if (err != RuntimeError::Success) {
                return std::unexpected(OrchestratorError::RuntimeError);
            }
        }

        RuntimeError runtime_folder = m_runtime->addFolder(result);
        if (runtime_folder != RuntimeError::Success) {
            return std::unexpected(OrchestratorError::RuntimeError);
        }

        return result["id"];
    }
    
    OrchestratorError BitwardenOrchestrator::renameFolder(ItemId uuid, 
        const Botan::secure_vector<uint8_t>& folder_name) {
        Entity entity;
        entity.type = EntityType::Folder;
        entity.id = uuid;

        std::expected<bool, RuntimeError> is_local = m_runtime->recordExists(entity);

        nlohmann::json result;

        std::expected<nlohmann::json, RuntimeError> folder_err = 
            m_runtime->getFolder(uuid);
        
        if (!folder_err.has_value()) {
            return OrchestratorError::RuntimeError;
        } else {
            result = folder_err.value();
        }

        if (!is_local.has_value() || !is_local.value()) {
            std::expected<nlohmann::json, NetworkError> folder_res = 
                m_network->renameFolder(uuid, folder_name);
            
            if (!folder_res.has_value()) {
                /**
                 * @note PendingChange requires the old base.
                 */
                PendingChange change;
                change.entity = entity;
                change.type = ChangeType::Updated;
                change.base = result;
                change.revision_date = utils::s_getCurrentTime();

                result["name"] = utils::getString(folder_name);

                RuntimeError record_err = m_runtime->record(change);
                if (record_err != RuntimeError::Success) {
                    return OrchestratorError::RuntimeError;
                }
            } else {
                result = folder_res.value();
            }
        }

        RuntimeError runtime_folder = m_runtime->updateFolder(uuid, result);

        if (runtime_folder != RuntimeError::Success) {
            return OrchestratorError::RuntimeError;
        }

        return OrchestratorError::Success;
    }
    
    OrchestratorError BitwardenOrchestrator::deleteFolder(ItemId uuid) {
        Entity entity;
        entity.type = EntityType::Folder;
        entity.id = uuid;

        std::expected<bool, RuntimeError> is_created_offline = 
            m_runtime->recordExists(entity);
        
        if (is_created_offline.has_value() && is_created_offline.value()) {
            m_runtime->removeRecord(entity);

            RuntimeError runtime_delete = m_runtime->removeFolder(uuid);
            if (runtime_delete != RuntimeError::Success) {
                return OrchestratorError::RuntimeError;
            }

            return OrchestratorError::Success;
        }

        std::expected<nlohmann::json, NetworkError> network_delete = m_network->deleteFolder(uuid);

        if (!network_delete.has_value()) {
            PendingChange change;
            change.entity = entity;
            change.type = ChangeType::Deleted;
            change.revision_date = utils::s_getCurrentTime();

            std::expected<nlohmann::json, RuntimeError> item_json = 
                m_runtime->getFolder(uuid);
            
            if (!item_json.has_value()) {
                return OrchestratorError::RuntimeError;
            }

            change.base = item_json.value();

            m_runtime->record(change);
        }

        RuntimeError runtime_delete = m_runtime->removeFolder(uuid);
        if (runtime_delete != RuntimeError::Success) {
            return OrchestratorError::RuntimeError;
        }

        return OrchestratorError::Success;
    }
    
    std::expected<std::string, OrchestratorError> BitwardenOrchestrator::downloadIcon(
        const Botan::secure_vector<uint8_t>& url) {
        std::string b64_url = utils::getString(utils::b64Encode(url));

        if (m_network->getConnectivity() == Connectivity::Offline &&
            !m_storage->exists(b64_url + ".png")) {
            return std::unexpected(OrchestratorError::NetworkError);
        }

        if (m_storage->exists(b64_url + ".failed")) {
            return std::unexpected(OrchestratorError::NetworkError);
        }

        if (!m_storage->exists(b64_url + ".png")) {
            std::expected<Botan::secure_vector<uint8_t>, NetworkError> result = 
                m_network->downloadIcon(url);

            if (!result.has_value()) {
                if (!m_storage->write(b64_url + ".failed", std::vector<uint8_t>{})) {
                    return std::unexpected(OrchestratorError::StorageFailure);
                }
                return std::unexpected(OrchestratorError::NetworkError);
            }

            if (!m_storage->write(b64_url + ".png", result.value())) {
                return std::unexpected(OrchestratorError::StorageFailure);
            }
        }

        return (m_storage->getPath() / std::filesystem::path(b64_url + ".png")).string();
    }
    
    Vendor BitwardenOrchestrator::getVendor() {
        return Vendor::BitWarden;
    }
}