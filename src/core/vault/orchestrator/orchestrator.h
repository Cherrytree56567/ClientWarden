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
        
        /**
         * @brief Compares the Security Stamp from the Local and Remote Profiles to determine if
         *  the session was invalidated.
         */
        virtual bool sessionInvalidated() = 0;

        /**
         * @brief NewItem pushes the new item to the server and then pushes it to the vault.
         */
        virtual std::expected<ItemId, NetworkError> newItem(nlohmann::json data) = 0;
        /**
         * @brief UpdateItem pushes the item to the server and then to the vault.
         */
        virtual NetworkError updateItem(nlohmann::json data) = 0;
        /**
         * @brief Asks the server to delete the item and remove it from the vault.
         */
        virtual NetworkError deleteItem(ItemId uuid) = 0;
        /**
         * @brief Asks the server to bin the item and bin it in the Vault.
         */
        virtual NetworkError softDeleteItem(ItemId uuid) = 0;
        /**
         * @brief Asks the server to restore the item and remove the item from the bin in the Vault.
         */
        virtual NetworkError restoreItem(ItemId uuid) = 0;
        /**
         * @brief Asks the server to archive the item and archive it in the Vault.
         */
        virtual NetworkError archiveItem(ItemId uuid) = 0;
        /**
         * @brief Asks the server to unarchive the item and unarchive it in the Vault.
         */
        virtual NetworkError unArchiveItem(ItemId uuid) = 0;
        /**
         * @brief Upload the attachment to the server and use on_progress to indicate progress.
         */
        virtual std::expected<Botan::secure_vector<uint8_t>, NetworkError> addAttachment(
            ItemId uuid, 
            const Botan::secure_vector<uint8_t>& file_contents, 
            const Botan::secure_vector<uint8_t>& file_name, 
            std::function<void(float)> on_progress = nullptr) = 0;
        /**
         * @brief Ask the server to remove the attachment and remove it from the Vault.
         */
        virtual NetworkError removeAttachment(ItemId uuid, 
            const Botan::secure_vector<uint8_t> attachment_id) = 0;
        /**
         * @brief Download the attachment from the server and indicate progress via on_progress.
         */
        virtual NetworkError downloadAttachment(ItemId uuid, 
            const Botan::secure_vector<uint8_t>& attachment_id, std::filesystem::path save_path,
            const ItemKey& key, std::function<void(float)> on_progress = nullptr) = 0;
        /**
         * @brief Ask the server to create a folder and add it to the Vault.
         */
        virtual std::expected<nlohmann::json, NetworkError> createFolder(
            const Botan::secure_vector<uint8_t>& folder_name) = 0;
        /**
         * @brief Ask the server to rename the folder and rename it in the Vault.
         */
        virtual NetworkError renameFolder(ItemId uuid, 
            const Botan::secure_vector<uint8_t>& folder_name) = 0;
        /**
         * @brief Ask the server to delete the folder and remove it from the Vault and all items
         *  inside the folder.
         */
        virtual NetworkError deleteFolder(ItemId uuid) = 0;
        /**
         * @brief Ask the server for the icon and return a botan vector of the item.
         */
        virtual std::expected<Botan::secure_vector<uint8_t>, NetworkError> downloadIcon(
            const Botan::secure_vector<uint8_t>& url) = 0;

        /**
         * @brief Retries pushing items that were created or modified offline.
         */
        virtual void retryOfflineItems() = 0;

        /**
         * @brief Returns the vendor.
         */
        virtual Vendor getVendor() = 0;
    protected:
        std::shared_ptr<Crypto> m_crypto;
        std::shared_ptr<Network> m_network;
        std::shared_ptr<Runtime> m_runtime;
    };
}