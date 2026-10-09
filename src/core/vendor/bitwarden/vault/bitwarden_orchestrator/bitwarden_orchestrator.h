#pragma once
#include "vault/orchestrator/orchestrator.h"

namespace clientwarden::vendor::bitwarden::vault {
    class BitwardenOrchestrator : public Orchestrator {
    public:
        explicit BitwardenOrchestrator(std::shared_ptr<Crypto> crypto, 
            std::shared_ptr<Network> network, std::shared_ptr<Runtime> runtime);
        ~BitwardenOrchestrator() override = default;
        
        std::expected<bool, OrchestratorError> sessionInvalidated() override;

        std::expected<ItemId, OrchestratorError> newItem(nlohmann::json data) override;
        OrchestratorError updateItem(nlohmann::json data) override;
        OrchestratorError deleteItem(ItemId uuid) override;
        OrchestratorError softDeleteItem(ItemId uuid) override;
        OrchestratorError restoreItem(ItemId uuid) override;
        OrchestratorError archiveItem(ItemId uuid) override;
        OrchestratorError unArchiveItem(ItemId uuid) override;
        std::expected<Botan::secure_vector<uint8_t>, OrchestratorError> addAttachment(
            ItemId uuid, 
            const Botan::secure_vector<uint8_t>& file_contents, 
            const Botan::secure_vector<uint8_t>& file_name, 
            std::function<void(float)> on_progress = nullptr) override;
        OrchestratorError removeAttachment(ItemId uuid, 
            const Botan::secure_vector<uint8_t> attachment_id) override;
        OrchestratorError downloadAttachment(ItemId uuid, 
            const Botan::secure_vector<uint8_t>& attachment_id, std::filesystem::path save_path,
            const ItemKey& key, std::function<void(float)> on_progress = nullptr) override;
        std::expected<nlohmann::json, OrchestratorError> createFolder(
            const Botan::secure_vector<uint8_t>& folder_name) override;
        OrchestratorError renameFolder(ItemId uuid, 
            const Botan::secure_vector<uint8_t>& folder_name) override;
        OrchestratorError deleteFolder(ItemId uuid) override;
        std::expected<Botan::secure_vector<uint8_t>, OrchestratorError> downloadIcon(
            const Botan::secure_vector<uint8_t>& url) override;

        OrchestratorError retryOfflineItems() override;

        Vendor getVendor() override;
    };
}