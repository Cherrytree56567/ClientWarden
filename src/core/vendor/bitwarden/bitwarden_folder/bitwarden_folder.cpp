#include "bitwarden_folder.h"

namespace clientwarden::vendor::bitwarden {
    BitwardenFolder::BitwardenFolder(Vault& vault, ItemId id, bool item_creation) : 
        Folder(vault, id, item_creation) {
        if (item_creation) {
            m_object_.id = utils::getUniqueId();
            m_object_.revision_date = std::chrono::system_clock::now();

            std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> name_err = 
                m_vault.getOrchestrator->getCrypto()->encrypt(utils::getSecureVector(""));
            
            if (!name_err.has_value()) {
                m_init = false;
                return;
            }
            
            m_object_.name = name_err.value();
        } else {
            std::expected<nlohmann::json, RuntimeError> folder_err = 
                m_vault.getOrchestrator()->getRuntime()->getFolder(id);
            
            if (!folder_err.has_value()) {
                m_init = false;
                return;
            }

            m_data_ = folder_err.value();

            if (!m_data_.contains("id") || !m_data_["id"].is_string() ||
                !m_data_.contains("name") || !m_data_["name"].is_string() ||
                !m_data_.contains("revisionDate") || !m_data_["revisionDate"].is_string()) {
                m_init = false;
                return;
            }

            m_object_.id = m_data_["id"];
            m_object_.revision_date = utils::s_getTime(m_data_["revisionDate"]);
            m_object_.name = utils::getSecureVector(m_data_["name"]);
        }

        m_init = true;
    }

    BitwardenFolder::~BitwardenFolder() {
        m_object_.id = "";
        m_object_.revision_date = std::chrono::system_clock::now();
        Botan::secure_scrub_memory(m_object_.name.data(), m_object_.name.size());
    }

    BitwardenFolder& BitwardenFolder::setName(const Botan::secure_vector<uint8_t>& name) {
        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> name_err = 
            m_vault.getOrchestrator()->getCrypto()->encrypt(name);
            
        if (!name_err.has_value()) {
            return *this;
        }
            
        m_object_.name = std::move(name_err.value());

        return *this;
    }

    BitwardenFolder& BitwardenFolder::getName(Botan::secure_vector<uint8_t>& o_name) {
        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> name_err = 
            m_vault.getOrchestrator()->getCrypto()->decrypt(m_object_.name);
            
        if (!name_err.has_value()) {
            return *this;
        }
            
        o_name = std::move(name_err.value());

        return *this;
    }

    BitwardenFolder& BitwardenFolder::getId(ItemId& o_id) {
        o_id = m_object_.id;

        return *this;
    }

    std::expected<ItemId, FolderError> BitwardenFolder::commitItem() {
        if (!m_is_created) {
            OrchestratorError err = 
                m_vault.getOrchestrator()->renameFolder(m_object_.id, m_object_.name);

            if (err != OrchestratorError::Success) {
                return std::unexpected(FolderError::OrchestratorError);
            }
        } else {
            std::expected<ItemId, OrchestratorError> err = m_vault.getOrchestrator()->createFolder(
                m_object_.name);
            
            if (!err.has_value()) {
                return std::unexpected(FolderError::OrchestratorError);
            }

            m_object_.id = err.value();
            m_is_created = false;
        }
        
        return m_object_.id;
    }

    std::expected<void, FolderError> BitwardenFolder::deleteItem() {
        if (m_is_created) {
            return {};
        }

        OrchestratorError err = 
            m_vault.getOrchestrator()->deleteFolder(m_object_.id);

        if (err != OrchestratorError::Success) {
            return std::unexpected(FolderError::OrchestratorError);
        }

        return {};
    }

    Vendor BitwardenFolder::getVendor() {
        return Vendor::BitWarden;
    }
}