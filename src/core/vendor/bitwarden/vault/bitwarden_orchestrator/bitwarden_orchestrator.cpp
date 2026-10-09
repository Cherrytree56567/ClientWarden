#include "bitwarden_orchestrator.h"

namespace clientwarden::vendor::bitwarden::vault {
    BitwardenOrchestrator::BitwardenOrchestrator(std::shared_ptr<Crypto> crypto, 
        std::shared_ptr<Network> network, std::shared_ptr<Runtime> runtime) :
        Orchestrator(crypto, network, runtime) {
        
    }

    std::expected<bool, OrchestratorError> BitwardenOrchestrator::sessionInvalidated() {
        std::expected<Profile, NetworkError> network_profile = m_network->getProfile();
        if (!network_profile.has_value()) {
            return std::unexpected(OrchestratorError::NetworkError);
        }

        std::expected<Profile, RuntimeError> runtime_profile = m_runtime->getProfile();
        if (!network_profile.has_value()) {
            return std::unexpected(OrchestratorError::RuntimeError);
        }
        
        return runtime_profile.security_stamp != network_profile.security_stamp;
    }
    
    /**
     * @note Data still requires a temp id which is then replaced by the server's id.
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

        if (network_item.has_value()) {
            created_offline = false;
            result_data = network_item.value();
        }

        if (!result_data.contains("id") || !result_data["id"].is_string()) {
            return std::unexpected(OrchestratorError::InvalidParams);
        }

        RuntimeError runtime_item = m_runtime->addItem(result_data);
        if (runtime_item != RuntimeError::Success) {
            return std::unexpected(OrchestratorError::RuntimeError);
        } else if (created_offline) {
            RuntimeError err = m_runtime->markOfflineCreatedItem(result_data["id"], true);
            if (err != RuntimeError::Success) {
                return std::unexpected(OrchestratorError::RuntimeError);
            }
        }

        return result_data["id"];
    }
    
    OrchestratorError BitwardenOrchestrator::updateItem(nlohmann::json data) {
        
    }
    
    OrchestratorError BitwardenOrchestrator::deleteItem(ItemId uuid) {
        
    }
    
    OrchestratorError BitwardenOrchestrator::softDeleteItem(ItemId uuid) {
        
    }
    
    OrchestratorError BitwardenOrchestrator::restoreItem(ItemId uuid) {
        
    }
    
    OrchestratorError BitwardenOrchestrator::archiveItem(ItemId uuid) {
        
    }
    
    OrchestratorError BitwardenOrchestrator::unArchiveItem(ItemId uuid) {
        
    }
    
    std::expected<Botan::secure_vector<uint8_t>, OrchestratorError> BitwardenOrchestrator::addAttachment(
        ItemId uuid, 
        const Botan::secure_vector<uint8_t>& file_contents, 
        const Botan::secure_vector<uint8_t>& file_name, 
        std::function<void(float)> on_progress) {
        
    }
    
    OrchestratorError BitwardenOrchestrator::removeAttachment(ItemId uuid, 
        const Botan::secure_vector<uint8_t> attachment_id) {
        
    }
    
    OrchestratorError BitwardenOrchestrator::downloadAttachment(ItemId uuid, 
        const Botan::secure_vector<uint8_t>& attachment_id, std::filesystem::path save_path,
        const ItemKey& key, std::function<void(float)> on_progress) {
        
    }
    
    std::expected<nlohmann::json, OrchestratorError> BitwardenOrchestrator::createFolder(
        const Botan::secure_vector<uint8_t>& folder_name) {
        
    }
    
    OrchestratorError BitwardenOrchestrator::renameFolder(ItemId uuid, 
        const Botan::secure_vector<uint8_t>& folder_name) {
        
    }
    
    OrchestratorError BitwardenOrchestrator::deleteFolder(ItemId uuid) {
        
    }
    
    std::expected<Botan::secure_vector<uint8_t>, OrchestratorError> BitwardenOrchestrator::downloadIcon(
        const Botan::secure_vector<uint8_t>& url) {
        
    }
    
    OrchestratorError BitwardenOrchestrator::retryOfflineItems() {
        
    }
    
    Vendor BitwardenOrchestrator::getVendor() {
        return Vendor::BitWarden;
    }
}