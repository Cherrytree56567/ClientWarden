#pragma once
#include <memory>
#include <expected>
#include <botan/secmem.h>
#include "clientwarden.h"
#include "../crypto/crypto.h"
#include "../network/network.h"
#include "../runtime/runtime.h"

namespace clientwarden::vault {
    class Orchestrator {
    public:
        Orchestrator(std::shared_ptr<Crypto> crypto, std::shared_ptr<Network> network,
            std::shared_ptr<Runtime> runtime);
        virtual ~Orchestrator() = default;
        
        virtual bool sessionInvalidated() = 0;

        /**
         * @brief NewItem pushes the new item to the server and then pushes it to the vault
         */
        virtual std::expected<ItemId, NetworkError> newItem(nlohmann::json data) = 0;
        virtual NetworkError updateItem(nlohmann::json data) = 0;
        virtual NetworkError deleteItem(ItemId uuid) = 0;
        virtual NetworkError softDeleteItem(ItemId uuid) = 0;
        virtual NetworkError restoreItem(ItemId uuid) = 0;
        virtual NetworkError archiveItem(ItemId uuid) = 0;
        virtual NetworkError unArchiveItem(ItemId uuid) = 0;
        virtual std::expected<Botan::secure_vector<uint8_t>, NetworkError> addAttachment(
            ItemId uuid, 
            const Botan::secure_vector<uint8_t>& file_contents, 
            const Botan::secure_vector<uint8_t>& file_name, 
            std::function<void(float)> on_progress = nullptr) = 0;
        virtual NetworkError removeAttachment(ItemId uuid, 
            const Botan::secure_vector<uint8_t> attachment_id) = 0;
        virtual NetworkError downloadAttachment(ItemId uuid, 
            const Botan::secure_vector<uint8_t>& attachment_id, std::filesystem::path save_path,
            const ItemKey& key, std::function<void(float)> on_progress = nullptr) = 0;
        virtual std::expected<nlohmann::json, NetworkError> createFolder(
            const Botan::secure_vector<uint8_t>& folder_name) = 0;
        virtual NetworkError renameFolder(ItemId uuid, 
            const Botan::secure_vector<uint8_t>& folder_name) = 0;
        virtual NetworkError deleteFolder(ItemId uuid) = 0;
        virtual std::expected<Botan::secure_vector<uint8_t>, NetworkError> downloadIcon(
            const Botan::secure_vector<uint8_t>& url) = 0;

        virtual void retryOfflineItems() = 0;

        virtual Vendor getVendor() = 0;
    protected:
        std::shared_ptr<Crypto> m_crypto;
        std::shared_ptr<Network> m_network;
        std::shared_ptr<Runtime> m_runtime;
    };
}