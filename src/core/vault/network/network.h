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
#include "thread/thread.h"
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

        /**
         * @brief Asks the server to create a new Item.
         */
        virtual std::expected<nlohmann::json, NetworkError> newItem(const nlohmann::json& data) = 0;
        /**
         * @brief Asks the server to update the item with the provided ItemId.
         */
        virtual std::expected<nlohmann::json, NetworkError> updateItem(const ItemId& uuid, 
            const nlohmann::json& data) = 0;
        /**
         * @brief Asks the server to delete the item with the provided ItemId.
         */
        virtual std::expected<nlohmann::json, NetworkError> deleteItem(const ItemId& uuid) = 0;
        /**
         * @brief Asks the server to bin the item with the provided ItemId.
         */
        virtual std::expected<nlohmann::json, NetworkError> softDeleteItem(const ItemId& uuid) = 0;
        /**
         * @brief Asks the server to restore the item with the provided ItemId.
         */
        virtual std::expected<nlohmann::json, NetworkError> restoreItem(const ItemId& uuid) = 0;
        /**
         * @brief Asks the server to archive the item with the provided ItemId.
         */
        virtual std::expected<nlohmann::json, NetworkError> archiveItem(const ItemId& uuid) = 0;
        /**
         * @brief Asks the server to unarchive the item with the provided ItemId.
         */
        virtual std::expected<nlohmann::json, NetworkError> unArchiveItem(const ItemId& uuid) = 0;

        /**
         * @brief Asks the server to create a folder with the provided name.
         */
        virtual std::expected<nlohmann::json, NetworkError> createFolder(const Botan::secure_vector<uint8_t>& name) = 0;
        /**
         * @brief Asks the server to rename the folder with the provided ItemId and name.
         */
        virtual std::expected<nlohmann::json, NetworkError> renameFolder(const ItemId& uuid, 
            const Botan::secure_vector<uint8_t>& name) = 0;
        /**
         * @brief Asks the server to delete the folder with the provided ItemId.
         */
        virtual std::expected<nlohmann::json, NetworkError> deleteFolder(const ItemId& uuid) = 0;
        
        /**
         * @brief Upload an attachment to the server and report progress via on_progress.
         */
        virtual std::expected<nlohmann::json, NetworkError> addAttachment(const ItemId& uuid, 
            const Botan::secure_vector<uint8_t>& name, const Botan::secure_vector<uint8_t>& contents,
            const Botan::secure_vector<uint8_t>& key, std::function<void(float)> on_progress = nullptr) = 0;
        /**
         * @brief Asks the server to remove the attachment with the provided ItemId and AttachmentId.
         */
        virtual std::expected<nlohmann::json, NetworkError> removeAttachment(const ItemId& uuid, 
            const Botan::secure_vector<uint8_t>& attachment_id) = 0;
        /**
         * @brief Download the attachment using the provided itemId and store it in o_data.
         */
        virtual std::expected<nlohmann::json, NetworkError> downloadAttachment(const ItemId& uuid, 
            const Botan::secure_vector<uint8_t>& attachment_id, 
            std::function<void(float)> on_progress = nullptr, 
            const Botan::secure_vector<uint8_t>& o_data) = 0;

        /**
         * @brief Download the icon with the provided url from the server.
         */
        virtual std::expected<Botan::secure_vector<uint8_t>, NetworkError> downloadIcon(
            const Botan::secure_vector<uint8_t>& url) = 0;
        /**
         * @brief Ask the server for the Vault Database.
         */
        virtual std::expected<nlohmann::json, NetworkError> getVault() = 0;
        /**
         * @brief Ask the server for the Remote version.
         */
        virtual std::expected<nlohmann::json, NetworkError> getVersion() = 0;
        /**
         * @brief Ask the server for the user's profile.
         */
        virtual std::expected<Profile, NetworkError> getProfile() = 0;

        /**
         * @brief Determine if the machine is offline or not.
         */
        virtual Connectivity getConnectivity() = 0;
        /**
         * @brief Determine if the accessToken is valid or not.
         */
        virtual NetworkError checkAccessTokenValidity() = 0;
        /**
         * @brief Ask the server to refresh our expired token.
         */
        virtual std::expected<nlohmann::json, NetworkError> refreshToken() = 0;

        /**
         * @brief Set the current AuthSession.
         */
        virtual void setSession(const AuthSession& session);
        /**
         * @brief Clear the current AuthSession.
         */
        virtual void eraseSession();

        /**
         * @brief Connect to the Websocket Server and notify on_event.
         */
        virtual NetworkError listen(std::function<void(NetworkEvent)> on_event) = 0;
        /**
         * @brief Close the WebSocket Connection and the thread.
         */
        virtual bool stopListening() = 0;

        /**
         * @brief Start the Token Refresh Thread.
         */
        virtual NetworkError startTokenRefreshThread() = 0;
        /**
         * @brief Stop the Token Refresh Thread.
         */
        virtual bool stopTokenRefreshThread() = 0;

        /**
         * @brief Return the Vendor.
         */
        virtual Vendor getVendor() = 0;
    protected:
        std::shared_ptr<Settings> m_settings;
        AuthSession m_session;
        std::jthread m_listening_thread;
        std::function<void(NetworkEvent)> m_on_event;
        Connectivity m_connectivity;
        Thread m_token_refresh;
    };
}