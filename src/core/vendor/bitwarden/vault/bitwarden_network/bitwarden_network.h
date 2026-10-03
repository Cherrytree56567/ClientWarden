#pragma once
#include <thread>
#include <optional>
#include <stop_token>
#define CPPHTTPLIB_EXPECT_100_THRESHOLD 0
#include <httplib.h>
#include <msgpack.hpp>
#include <nlohmann/json.hpp>
#include "vault/network/network.h"

namespace clientwarden::vendor::bitwarden::vault {
    class BitwardenNetwork {
    public:
        explicit BitwardenNetwork(std::shared_ptr<Settings> settings);
        ~BitwardenNetwork() override = default;

        /**
         * @brief See `network.h` - Network for all briefs
         */
        std::expected<void, NetworkError> setURLs(const std::vector<Botan::secure_vector<uint8_t>>& urls) override;
        std::vector<std::string> requiredURLs() override;

        std::expected<PreLoginResult, NetworkError> preLogin(const Botan::secure_vector<uint8_t>& email) override;
        std::expected<TokenResult, NetworkError> getToken(const Botan::secure_vector<uint8_t>& email, 
            const Botan::secure_vector<uint8_t>& master_password_hash) override;
        std::expected<TokenResult, NetworkError> getToken2FA(const Botan::secure_vector<uint8_t>& email, 
            const Botan::secure_vector<uint8_t>& master_password_hash, const MultiFactorProof& proof) override;

        std::expected<nlohmann::json, NetworkError> newItem(const nlohmann::json& data) override;
        std::expected<nlohmann::json, NetworkError> updateItem(const ItemId& uuid, 
            const nlohmann::json& data) override;
        std::expected<nlohmann::json, NetworkError> deleteItem(const ItemId& uuid) override;
        std::expected<nlohmann::json, NetworkError> softDeleteItem(const ItemId& uuid) override;
        std::expected<nlohmann::json, NetworkError> restoreItem(const ItemId& uuid) override;
        std::expected<nlohmann::json, NetworkError> archiveItem(const ItemId& uuid) override;
        std::expected<nlohmann::json, NetworkError> unArchiveItem(const ItemId& uuid) override;

        std::expected<nlohmann::json, NetworkError> createFolder(const Botan::secure_vector<uint8_t>& name) override;
        std::expected<nlohmann::json, NetworkError> renameFolder(const ItemId& uuid, 
            const Botan::secure_vector<uint8_t>& name) override;
        std::expected<nlohmann::json, NetworkError> deleteFolder(const ItemId& uuid) override;
        
        std::expected<nlohmann::json, NetworkError> addAttachment(const ItemId& uuid, 
            const Botan::secure_vector<uint8_t>& name, const Botan::secure_vector<uint8_t>& contents,
            const Botan::secure_vector<uint8_t>& key, std::function<void(float)> on_progress = nullptr) override;
        std::expected<nlohmann::json, NetworkError> removeAttachment(const ItemId& uuid, 
            const Botan::secure_vector<uint8_t>& attachment_id) override;
        std::expected<nlohmann::json, NetworkError> downloadAttachment(const ItemId& uuid, 
            const Botan::secure_vector<uint8_t>& attachment_id, 
            std::function<void(float)> on_progress = nullptr, 
            const Botan::secure_vector<uint8_t>& o_data) override;

        std::expected<Botan::secure_vector<uint8_t>, NetworkError> downloadIcon(
            const Botan::secure_vector<uint8_t>& url) override;
        std::expected<nlohmann::json, NetworkError> getVault() override;
        std::expected<nlohmann::json, NetworkError> getVersion() override;
        std::expected<Profile, NetworkError> getProfile() override;

        Connectivity getConnectivity() override;
        NetworkError checkAccessTokenValidity() override;
        std::expected<nlohmann::json, NetworkError> refreshToken() override;

        void setSession(const AuthSession& session);
        void eraseSession();

        NetworkError listen(std::function<void(NetworkEvent)> on_event) override;
        bool stopListening() override;

        NetworkError startTokenRefreshThread() override;
        bool stopTokenRefreshThread() override;

        Vendor getVendor() override;
    private:
        bool m_init_ = false;
        std::shared_ptr<httplib::Client> m_api_client_;
        std::shared_ptr<httplib::Client> m_vault_client_;
        std::shared_ptr<httplib::Client> m_icon_client_;
        std::mutex m_api_client_mutex_;
        std::mutex m_vault_client_mutex_;
        std::mutex m_icon_client_mutex_;
    };
}