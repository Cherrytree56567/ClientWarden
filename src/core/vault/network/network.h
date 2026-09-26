#pragma once
#define CPPHTTPLIB_EXPECT_100_THRESHOLD 0
#include <vector>
#include <memory>
#include <variant>
#include <expected>
#include <functional>
#include <httplib.h>
#include <botan/secmem.h>
#include <nlohmann/json.hpp>
#include "../settings/settings.h"
#include "../profiles/profile.h"
#include "clientwarden.h"

namespace clientwarden::vault {
    /**
     * @brief Holds the enum to identify what state the Network is in
     */
    enum class Connectivity {
        Offline,
        Online
    };

    /**
     * @brief NetworkError is used as a result to provide a reason for failure
     */
    enum class NetworkError {
        OfflineNetwork,
        Unauthorised,
        RateLimited,
        Invalid,
        ServerError,
        Unknown,
        Success
    };

    /**
     * @brief Provides the result for the preLogin()
     */
    struct PreLoginResult {
        KDFParams params;
        nlohmann::json raw;
    };

    /**
     * @brief Provides the successful result for getToken()
     */
    struct AuthResult {
        AuthSession session;
        nlohmann::json raw;
    };

    /**
     * @brief Used to identify the type of Auth required
     */
    enum class MultiFactorAuth {
        TOTP,
        DeviceVerification,
        Passkey,
        Duo
    };

    /**
     * @brief Used to provide the 2FA methods allowed
     */
    struct MultiFactorChallenge {
        std::vector<MultiFactorAuth> available_methods;
        nlohmann::json raw;
    };

    using TokenResult = std::variant<AuthResult, MultiFactorChallenge>;

    /**
     * @brief Used to provide getToken() with a 2FA arg to login
     */
    struct MultiFactorProof {
        MultiFactorAuth method;
        Botan::secure_vector<uint8_t> code;
        bool remember = false;
    };

    /**
     * @brief Used to provide details on what changed during a network websocket event.
     */
    enum class NetworkEvent {
        CipherUpdated,
        CipherCreated,
        CipherDeleted,
        FolderDeleted,
        AllCiphersChanged,
        WholeVaultChanged,
        OrgKeysChanged,
        FolderCreated,
        FolderUpdated,
        CipherBinned,
        AccountSettingsChanged,
        LogOut
    };

    class Network {
    public:
        Network(std::shared_ptr<Settings> settings);
        virtual ~Network() = default;

        /**
         * @brief Vendor chooses how many urls to use. It should store the URLs in keychain using
         * Settings and retrieve them later in the constructor.
         */
        virtual std::expected<void, NetworkError> setURLs(const std::vector<Botan::secure_vector<uint8_t>>& urls) = 0;

        /**
         * @brief Gets Prelogin Info like KDF Params and checks if the email is valid.
         */
        virtual std::expected<PreLoginResult, NetworkError> preLogin(const Botan::secure_vector<uint8_t>& email) = 0;
        /**
         * @brief getToken requests for a token using email and password. If it fails or requires
         * 2FA, it returns with a MultiFactorChallenge.
         */
        virtual std::expected<TokenResult, NetworkError> getToken(const Botan::secure_vector<uint8_t>& email, 
            const Botan::secure_vector<uint8_t>& master_password_hash) = 0;
        /**
         * @brief getToken2FA requests for a token using 2FA auth + email and password. If it 
         * requires additional 2FA, it will return a MultiFactorChallenge.
         */
        virtual std::expected<TokenResult, NetworkError> getToken2FA(const Botan::secure_vector<uint8_t>& email, 
            const Botan::secure_vector<uint8_t>& master_password_hash, const MultiFactorProof& proof) = 0;

        virtual std::expected<nlohmann::json, NetworkError> newItem(const nlohmann::json& data) = 0;
        virtual std::expected<nlohmann::json, NetworkError> updateItem(const ItemId& uuid, 
            const nlohmann::json& data) = 0;
        virtual std::expected<nlohmann::json, NetworkError> deleteItem(const ItemId& uuid) = 0;
        virtual std::expected<nlohmann::json, NetworkError> softDeleteItem(const ItemId& uuid) = 0;
        virtual std::expected<nlohmann::json, NetworkError> restoreItem(const ItemId& uuid) = 0;
        virtual std::expected<nlohmann::json, NetworkError> archiveItem(const ItemId& uuid) = 0;
        virtual std::expected<nlohmann::json, NetworkError> unArchiveItem(const ItemId& uuid) = 0;

        virtual std::expected<nlohmann::json, NetworkError> createFolder(const Botan::secure_vector<uint8_t>& name) = 0;
        virtual std::expected<nlohmann::json, NetworkError> renameFolder(const ItemId& uuid, 
            const Botan::secure_vector<uint8_t>& name) = 0;
        virtual std::expected<nlohmann::json, NetworkError> deleteFolder(const ItemId& uuid) = 0;
        
        virtual std::expected<nlohmann::json, NetworkError> addAttachment(const ItemId& uuid, 
            const Botan::secure_vector<uint8_t>& name, const Botan::secure_vector<uint8_t>& contents,
            const Botan::secure_vector<uint8_t>& key, std::function<void(float)> on_progress = nullptr) = 0;
        virtual std::expected<nlohmann::json, NetworkError> removeAttachment(const ItemId& uuid, 
            const Botan::secure_vector<uint8_t>& attachment_id) = 0;
        virtual std::expected<nlohmann::json, NetworkError> downloadAttachment(const ItemId& uuid, 
            const Botan::secure_vector<uint8_t>& attachment_id, 
            std::function<void(float)> on_progress = nullptr) = 0;

        virtual std::expected<Botan::secure_vector<uint8_t>, NetworkError> downloadIcon(
            const Botan::secure_vector<uint8_t>& url) = 0;
        virtual std::expected<nlohmann::json, NetworkError> getVault() = 0;
        virtual std::expected<nlohmann::json, NetworkError> getVersion() = 0;
        virtual std::expected<Profile, NetworkError> getProfile() = 0;

        virtual Connectivity getConnectivity() = 0;
        virtual NetworkError checkAccessTokenValidity() = 0;
        virtual std::expected<nlohmann::json, NetworkError> refreshToken() = 0;

        virtual void setSession(const AuthSession& session);
        virtual void eraseSession();

        virtual NetworkError listen(std::function<void(NetworkEvent)> on_event) = 0;
        virtual bool stopListening() = 0;

        virtual Vendor getVendor() = 0;
    protected:
        std::shared_ptr<Settings> m_settings;
        AuthSession m_session;
        std::jthread m_listening_thread;
        std::function<void(NetworkEvent)> m_on_event;
        Connectivity m_connectivity;
    };
}