#include "bitwarden_network.h"

constexpr MultiFactorAuth toMultiFactorAuth(TwoFactorProviderType type) {
    switch (type) {
    case TwoFactorProviderType::Authenticator: 
        return MultiFactorAuth::TOTP;

    case TwoFactorProviderType::Email: 
        return MultiFactorAuth::Email;

    case TwoFactorProviderType::Duo: 
        return MultiFactorAuth::Duo;

    case TwoFactorProviderType::OrganizationDuo: 
        return MultiFactorAuth::OrganizationDuo;

    case TwoFactorProviderType::Yubikey: 
        return MultiFactorAuth::YubiKey;

    case TwoFactorProviderType::U2f: 
        return MultiFactorAuth::U2F;

    case TwoFactorProviderType::Remember: 
        return MultiFactorAuth::RememberToken;

    case TwoFactorProviderType::WebAuthn: 
        return MultiFactorAuth::Passkey;

    case TwoFactorProviderType::RecoveryCode: 
        return MultiFactorAuth::RecoveryCode;

    default:
        return MultiFactorAuth::TOTP;
    }
  
    return MultiFactorAuth::TOTP;
}

namespace clientwarden::vendor::bitwarden::vault {
    BitwardenNetwork::BitwardenNetwork(std::shared_ptr<Settings> settings) : m_settings(settings) {

    }

    /**
     * @brief Requests a list of URLS in the following format:
     *  - Main URL
     *  - API URL
     *  - Vault URL
     *  - Icon URL
     *  - WebSocket URL
     */
    std::expected<void, NetworkError> BitwardenNetwork::setURLs(const std::vector<Botan::secure_vector<uint8_t>>& urls) {
        if (urls.size() != 5) {
            return std::unexpected(NetworkError::InvalidParams);
        }

        for (const Botan::secure_vector<uint8_t>& url : urls) {
            std::string str_url = std::string(url.begin(), url.end());
            
            boost::system::result<boost::urls::url_view> url_parse = 
                boost::urls::parse_uri(str_url);
            
            if (!url_parse) {
                return std::unexpected(NetworkError::InvalidParams);
            }

            const boost::urls::url_view& url_view = url_parse.value();

            boost::urls::scheme scheme = url_view.scheme_id();
            if (url == urls[4]) {
                std::string_view url_scheme = url_view.scheme();
                if (url_scheme != "ws" && url_scheme != "wss") {
                    return std::unexpected(NetworkError::InvalidParams);
                }
            } else {
                if (scheme != boost::urls::scheme::http &&
                    scheme != boost::urls::scheme::https) {
                    return std::unexpected(NetworkError::InvalidParams);
                }
            }

            if (!url_view.has_authority() || url_view.host().empty()) {
                return std::unexpected(NetworkError::InvalidParams);
            }
        }

        m_urls = urls;
        
        m_api_client_ = std::make_shared<httplib::Client>(std::string(urls[1].begin(), urls[1].end()));
        m_api_client_->set_connection_timeout(5);
        m_vault_client_ = std::make_shared<httplib::Client>(std::string(urls[2].begin(), urls[2].end()));
        m_vault_client_->set_connection_timeout(5);
        m_icon_client_ = std::make_shared<httplib::Client>(std::string(urls[3].begin(), urls[3].end()));
        m_icon_client_->set_connection_timeout(2);
        m_icon_client_->set_read_timeout(3);

        std::expected<void, SettingsError> main_result = 
            m_settings->keychainSet(KeychainSecurity::Secure, "mainUrl", urls[0]);
        
        if (!main_result.has_value()) {
            return std::unexpected(NetworkError::SettingsError);
        }

        std::expected<void, SettingsError> api_result = 
            m_settings->keychainSet(KeychainSecurity::Secure, "apiUrl", urls[1]);
        
        if (!api_result.has_value()) {
            return std::unexpected(NetworkError::SettingsError);
        }

        std::expected<void, SettingsError> vault_result = 
            m_settings->keychainSet(KeychainSecurity::Secure, "vaultUrl", urls[2]);
        
        if (!vault_result.has_value()) {
            return std::unexpected(NetworkError::SettingsError);
        }

        std::expected<void, SettingsError> icon_result = 
            m_settings->keychainSet(KeychainSecurity::Secure, "iconUrl", urls[3]);
        
        if (!icon_result.has_value()) {
            return std::unexpected(NetworkError::SettingsError);
        }

        std::expected<void, SettingsError> wss_result = 
            m_settings->keychainSet(KeychainSecurity::Secure, "webSocketUrl", urls[4]);
        
        if (!wss_result.has_value()) {
            return std::unexpected(NetworkError::SettingsError);
        }

        m_init_ = true;

        return {};
    }
    
    std::vector<std::string> BitwardenNetwork::requiredURLs() {
        std::vector<std::string> result;
        result.push_back("Main URL");
        result.push_back("API URL");
        result.push_back("Vault URL");
        result.push_back("Icon URL");
        result.push_back("WebSocket URL");

        return result;
    }
    
    std::expected<PreLoginResult, NetworkError> BitwardenNetwork::preLogin(const Botan::secure_vector<uint8_t>& email) {
        if (!m_init_) {
            return std::unexpected(NetworkError::Uninitialised);
        }

        if (m_connectivity == Connectivity::Offline) {
            return std::unexpected(NetworkError::OfflineNetwork);
        }

        std::lock_guard<std::mutex> lock(m_vault_client_mutex_);

        httplib::Headers headers = {
            { "Content-Type", "application/json" },
            { "bitwarden-client-name", bitwarden_device_type },
            { "bitwarden-client-version", bitwarden_version },
        };

        nlohmann::json payload;
        payload["email"] = std::string(email.begin(), email.end());

        httplib::Result res = m_vault_client_->Post("/identity/accounts/prelogin", headers, 
            payload.dump(), "application/json");

        std::expected<void, NetworkError> err = getError_(res);

        if (!err.has_value()) {
            return std::unexpected(err.error());
        }

        if (!nlohmann::json::accept(res->body)) {
            return std::unexpected(NetworkError::Invalid);
        }

        PreLoginResult result;
        result.raw = nlohmann::json::parse(res->body);

        if (!result.raw.contains("kdf") || !result.raw["kdf"].is_number_integer() || 
            !result.raw.contains("kdfIterations") || !result.raw["kdfIterations"].is_number_integer()) {
            return std::unexpected(NetworkError::Invalid);
        }

        result.params.type = static_cast<KDFType>(result.raw["kdf"].get<int>());
        result.params.iterations = result.raw["kdfIterations"].get<int>();

        if (result.params.type == KDFType::Argon2ID &&
            (!result.raw.contains("kdfMemory") || !result.raw["kdfMemory"].is_number_integer() ||
            !result.raw.contains("kdfParallelism") || !result.raw["kdfParallelism"].is_number_integer())) {
            return std::unexpected(NetworkError::Invalid);
        }

        if (result.params.type == KDFType::Argon2ID) {
            result.params.memory = result.raw["kdfMemory"].get<int>();
            result.params.parallel = result.raw["kdfParallelism"].get<int>();
        }

        return result;
    }

    std::expected<TokenResult, NetworkError> BitwardenNetwork::getToken(const Botan::secure_vector<uint8_t>& email, 
        const Botan::secure_vector<uint8_t>& master_password_hash) {
        if (!m_init_) {
            return std::unexpected(NetworkError::Uninitialised);
        }
        
        if (m_connectivity == Connectivity::Offline) {
            return std::unexpected(NetworkError::OfflineNetwork);
        }

        httplib::Params data;
        data.emplace("grant_type", "password");
        data.emplace("username", str_email);
        data.emplace("password", str_master_password_hash);
        data.emplace("scope", "api offline_access");
        data.emplace("client_id", bitwarden_client);
        data.emplace("deviceType", bitwarden_device_type);
        data.emplace("deviceIdentifier", utils::getUniqueId());
        data.emplace("deviceName", bitwarden_device_name);

        return getToken_(data);
    }
    
    std::expected<TokenResult, NetworkError> BitwardenNetwork::getToken2FA(const Botan::secure_vector<uint8_t>& email, 
        const Botan::secure_vector<uint8_t>& master_password_hash, const MultiFactorProof& proof) {
        if (!m_init_) {
            return std::unexpected(NetworkError::Uninitialised);
        }
        
        if (m_connectivity == Connectivity::Offline) {
            return std::unexpected(NetworkError::OfflineNetwork);
        }

        std::string code(proof.code.begin(), proof.code.end());

        httplib::Params data;
        data.emplace("grant_type", "password");
        data.emplace("username", str_email);
        data.emplace("password", str_master_password_hash);
        data.emplace("scope", "api offline_access");
        data.emplace("client_id", bitwarden_client);
        data.emplace("deviceType", bitwarden_device_type);
        data.emplace("deviceIdentifier", utils::getUniqueId());
        data.emplace("deviceName", bitwarden_device_name);

        /**
         * @todo Double Check at some point and it should be separated into a separate one that uses
         *  TwoFactorProviderType from bitwarden.h
         */
        if (proof.method == MultiFactorAuth::Email) {
            data.emplace("newDeviceOtp", code);
        } else {
            data.emplace("twoFactorToken", code);
            data.emplace("twoFactorProvider", std::to_string(static_cast<int>(toMultiFactorAuth(proof.method))));
            data.emplace("twoFactorRemember", proof.remember ? "1" : "0");
        }

        return getToken_(data);
    }
    
    std::expected<nlohmann::json, NetworkError> BitwardenNetwork::newItem(const nlohmann::json& data) {
        if (!m_init_) {
            return std::unexpected(NetworkError::Uninitialised);
        }
        
        if (m_connectivity == Connectivity::Offline) {
            return std::unexpected(NetworkError::OfflineNetwork);
        }

        std::string access_token = getString(m_session.access_token);

        std::lock_guard<std::mutex> lock(m_vault_client_mutex_);
        httplib::Headers headers = {
            { "Authorization", "Bearer " + access_token },
            { "Content-Type", "application/json" },
            { "bitwarden-client-name", bitwarden_device_type },
            { "bitwarden-client-version", bitwarden_version },
        };

        Botan::secure_scrub_memory(access_token.data(), access_token.size());

        httplib::Result res = m_vault_client->Post("/api/ciphers", headers, data.dump(), "application/json");

        std::expected<void, NetworkError> err = getError_(res);

        if (!err.has_value()) {
            return std::unexpected(err.error());
        }

        if (!nlohmann::json::accept(res->body)) {
            return std::unexpected(NetworkError::Unknown);
        }

        return nlohmann::json::parse(res->body);
    }
    
    std::expected<nlohmann::json, NetworkError> BitwardenNetwork::updateItem(const ItemId& uuid, 
        const nlohmann::json& data) {
        if (!m_init_) {
            return std::unexpected(NetworkError::Uninitialised);
        }
        
        if (m_connectivity == Connectivity::Offline) {
            return std::unexpected(NetworkError::OfflineNetwork);
        }

        std::string access_token = getString(m_session.access_token);

        std::lock_guard<std::mutex> lock(m_vault_client_mutex_);
        httplib::Headers headers = {
            { "Authorization", "Bearer " + access_token },
            { "Content-Type", "application/json" },
            { "bitwarden-client-name", bitwarden_device_type },
            { "bitwarden-client-version", bitwarden_version },
        };

        Botan::secure_scrub_memory(access_token.data(), access_token.size());

        httplib::Result res = m_vault_client->Put("/api/ciphers/" + uuid, headers, data.dump(), "application/json");

        std::expected<void, NetworkError> err = getError_(res);

        if (!err.has_value()) {
            return std::unexpected(err.error());
        }

        if (!nlohmann::json::accept(res->body)) {
            return std::unexpected(NetworkError::Unknown);
        }

        return nlohmann::json::parse(res->body);
    }
    
    std::expected<nlohmann::json, NetworkError> BitwardenNetwork::deleteItem(const ItemId& uuid) {
        if (!m_init_) {
            return std::unexpected(NetworkError::Uninitialised);
        }
        
        if (m_connectivity == Connectivity::Offline) {
            return std::unexpected(NetworkError::OfflineNetwork);
        }

        std::string access_token = getString(m_session.access_token);

        std::lock_guard<std::mutex> lock(m_vault_client_mutex_);
        httplib::Headers headers = {
            { "Authorization", "Bearer " + access_token },
            { "Content-Type", "application/json" },
            { "bitwarden-client-name", bitwarden_device_type },
            { "bitwarden-client-version", bitwarden_version },
        };

        Botan::secure_scrub_memory(access_token.data(), access_token.size());

        httplib::Result res = m_vault_client->Delete("/api/ciphers/" + uuid, headers);

        std::expected<void, NetworkError> err = getError_(res);

        if (!err.has_value()) {
            return std::unexpected(err.error());
        }

        if (!nlohmann::json::accept(res->body)) {
            return std::unexpected(NetworkError::Unknown);
        }

        return nlohmann::json::parse(res->body);
    }
    
    std::expected<nlohmann::json, NetworkError> BitwardenNetwork::softDeleteItem(const ItemId& uuid) {
        if (!m_init_) {
            return std::unexpected(NetworkError::Uninitialised);
        }
        
        if (m_connectivity == Connectivity::Offline) {
            return std::unexpected(NetworkError::OfflineNetwork);
        }

        std::string access_token = getString(m_session.access_token);

        std::lock_guard<std::mutex> lock(m_vault_client_mutex_);
        httplib::Headers headers = {
            { "Authorization", "Bearer " + access_token },
            { "Content-Type", "application/json" },
            { "bitwarden-client-name", bitwarden_device_type },
            { "bitwarden-client-version", bitwarden_version },
        };

        Botan::secure_scrub_memory(access_token.data(), access_token.size());

        httplib::Result res = m_vault_client->Put("/api/ciphers/" + uuid + "/delete", headers, "", "application/json");

        std::expected<void, NetworkError> err = getError_(res);

        if (!err.has_value()) {
            return std::unexpected(err.error());
        }

        if (!nlohmann::json::accept(res->body)) {
            return std::unexpected(NetworkError::Unknown);
        }

        return nlohmann::json::parse(res->body);
    }
    
    std::expected<nlohmann::json, NetworkError> BitwardenNetwork::restoreItem(const ItemId& uuid) {
        if (!m_init_) {
            return std::unexpected(NetworkError::Uninitialised);
        }
        
        if (m_connectivity == Connectivity::Offline) {
            return std::unexpected(NetworkError::OfflineNetwork);
        }

        std::string access_token = getString(m_session.access_token);

        std::lock_guard<std::mutex> lock(m_vault_client_mutex_);
        httplib::Headers headers = {
            { "Authorization", "Bearer " + access_token },
            { "Content-Type", "application/json" },
            { "bitwarden-client-name", bitwarden_device_type },
            { "bitwarden-client-version", bitwarden_version },
        };

        Botan::secure_scrub_memory(access_token.data(), access_token.size());

        httplib::Result res = m_vault_client->Put("/api/ciphers/" + uuid + "/restore", headers, "", "application/json");

        std::expected<void, NetworkError> err = getError_(res);

        if (!err.has_value()) {
            return std::unexpected(err.error());
        }

        if (!nlohmann::json::accept(res->body)) {
            return std::unexpected(NetworkError::Unknown);
        }

        return nlohmann::json::parse(res->body);
    }
    
    std::expected<nlohmann::json, NetworkError> BitwardenNetwork::archiveItem(const ItemId& uuid) {
        if (!m_init_) {
            return std::unexpected(NetworkError::Uninitialised);
        }
        
        if (m_connectivity == Connectivity::Offline) {
            return std::unexpected(NetworkError::OfflineNetwork);
        }

        std::string access_token = getString(m_session.access_token);

        std::lock_guard<std::mutex> lock(m_vault_client_mutex_);
        httplib::Headers headers = {
            { "Authorization", "Bearer " + access_token },
            { "Content-Type", "application/json" },
            { "bitwarden-client-name", bitwarden_device_type },
            { "bitwarden-client-version", bitwarden_version },
        };

        Botan::secure_scrub_memory(access_token.data(), access_token.size());

        nlohmann::json json_data;
        json_data["ids"] = nlohmann::json::array();
        json_data["ids"][0] = uuid;

        httplib::Result res = m_vault_client->Post("/api/ciphers/archive", headers, json_data.dump(), "application/json");

        std::expected<void, NetworkError> err = getError_(res);

        if (!err.has_value()) {
            return std::unexpected(err.error());
        }

        if (!nlohmann::json::accept(res->body)) {
            return std::unexpected(NetworkError::Unknown);
        }

        return nlohmann::json::parse(res->body);
    }
    
    std::expected<nlohmann::json, NetworkError> BitwardenNetwork::unArchiveItem(const ItemId& uuid) {
        if (!m_init_) {
            return std::unexpected(NetworkError::Uninitialised);
        }
        
        if (m_connectivity == Connectivity::Offline) {
            return std::unexpected(NetworkError::OfflineNetwork);
        }

        std::string access_token = getString(m_session.access_token);

        std::lock_guard<std::mutex> lock(m_vault_client_mutex_);
        httplib::Headers headers = {
            { "Authorization", "Bearer " + access_token },
            { "Content-Type", "application/json" },
            { "bitwarden-client-name", bitwarden_device_type },
            { "bitwarden-client-version", bitwarden_version },
        };

        Botan::secure_scrub_memory(access_token.data(), access_token.size());

        nlohmann::json json_data;
        json_data["ids"] = nlohmann::json::array();
        json_data["ids"][0] = uuid;

        httplib::Result res = m_vault_client->Post("/api/ciphers/unarchive", headers, json_data.dump(), "application/json");

        std::expected<void, NetworkError> err = getError_(res);

        if (!err.has_value()) {
            return std::unexpected(err.error());
        }

        if (!nlohmann::json::accept(res->body)) {
            return std::unexpected(NetworkError::Unknown);
        }

        return nlohmann::json::parse(res->body);
    }
    
    std::expected<nlohmann::json, NetworkError> BitwardenNetwork::createFolder(const Botan::secure_vector<uint8_t>& name) {
        if (!m_init_) {
            return std::unexpected(NetworkError::Uninitialised);
        }
        
        if (m_connectivity == Connectivity::Offline) {
            return std::unexpected(NetworkError::OfflineNetwork);
        }

        std::string access_token = getString(m_session.access_token);

        std::lock_guard<std::mutex> lock(m_vault_client_mutex_);
        httplib::Headers headers = {
            { "Authorization", "Bearer " + access_token },
            { "Content-Type", "application/json" },
            { "bitwarden-client-name", bitwarden_device_type },
            { "bitwarden-client-version", bitwarden_version },
        };

        Botan::secure_scrub_memory(access_token.data(), access_token.size());

        nlohmann::json json_data;
        json_data["name"] = utils::getString(name);

        httplib::Result res = m_vault_client->Post("/api/folders", headers, json_data.dump(), "application/json");

        std::expected<void, NetworkError> err = getError_(res);

        if (!err.has_value()) {
            return std::unexpected(err.error());
        }

        if (!nlohmann::json::accept(res->body)) {
            return std::unexpected(NetworkError::Unknown);
        }

        return nlohmann::json::parse(res->body);
    }
    
    std::expected<nlohmann::json, NetworkError> BitwardenNetwork::renameFolder(const ItemId& uuid, 
        const Botan::secure_vector<uint8_t>& name) {
        if (!m_init_) {
            return std::unexpected(NetworkError::Uninitialised);
        }
        
        if (m_connectivity == Connectivity::Offline) {
            return std::unexpected(NetworkError::OfflineNetwork);
        }

        std::string access_token = getString(m_session.access_token);

        std::lock_guard<std::mutex> lock(m_vault_client_mutex_);
        httplib::Headers headers = {
            { "Authorization", "Bearer " + access_token },
            { "Content-Type", "application/json" },
            { "bitwarden-client-name", bitwarden_device_type },
            { "bitwarden-client-version", bitwarden_version },
        };

        Botan::secure_scrub_memory(access_token.data(), access_token.size());

        nlohmann::json json_data;
        json_data["name"] = utils::getString(name);

        httplib::Result res = m_vault_client->Put("/api/folders/" + uuid, headers, json_data.dump(), "application/json");

        std::expected<void, NetworkError> err = getError_(res);

        if (!err.has_value()) {
            return std::unexpected(err.error());
        }

        if (!nlohmann::json::accept(res->body)) {
            return std::unexpected(NetworkError::Unknown);
        }

        return nlohmann::json::parse(res->body);
    }
    
    std::expected<nlohmann::json, NetworkError> BitwardenNetwork::deleteFolder(const ItemId& uuid) {
        if (!m_init_) {
            return std::unexpected(NetworkError::Uninitialised);
        }
        
        if (m_connectivity == Connectivity::Offline) {
            return std::unexpected(NetworkError::OfflineNetwork);
        }

        std::string access_token = getString(m_session.access_token);

        std::lock_guard<std::mutex> lock(m_vault_client_mutex_);
        httplib::Headers headers = {
            { "Authorization", "Bearer " + access_token },
            { "Content-Type", "application/json" },
            { "bitwarden-client-name", bitwarden_device_type },
            { "bitwarden-client-version", bitwarden_version },
        };

        Botan::secure_scrub_memory(access_token.data(), access_token.size());

        httplib::Result res = m_vault_client->Delete("/api/folders/" + uuid, headers);

        std::expected<void, NetworkError> err = getError_(res);

        if (!err.has_value()) {
            return std::unexpected(err.error());
        }

        if (!nlohmann::json::accept(res->body)) {
            return std::unexpected(NetworkError::Unknown);
        }

        return nlohmann::json::parse(res->body);
    }
    
    std::expected<nlohmann::json, NetworkError> BitwardenNetwork::addAttachment(const ItemId& uuid, 
        const Botan::secure_vector<uint8_t>& name, const Botan::secure_vector<uint8_t>& contents,
        const Botan::secure_vector<uint8_t>& key, std::function<void(float)> on_progress) {
        if (!m_init_) {
            return std::unexpected(NetworkError::Uninitialised);
        }
        
        if (m_connectivity == Connectivity::Offline) {
            return std::unexpected(NetworkError::OfflineNetwork);
        }

        std::string access_token = getString(m_session.access_token);

        std::unique_lock<std::mutex> lock(m_vault_client_mutex_);
        httplib::Headers headers = {
            { "Authorization", "Bearer " + access_token },
            { "Content-Type", "application/json" },
            { "bitwarden-client-name", bitwarden_device_type },
            { "bitwarden-client-version", bitwarden_version },
        };

        Botan::secure_scrub_memory(access_token.data(), access_token.size());

        std::string dec_name = utils::getString(name);
        std::string dec_key = utils::getString(key);

        nlohmann::json json_data;
        json_data["adminRequest"] = false;
        json_data["fileName"] = dec_name;
        json_data["fileSize"] = contents.size();
        json_data["key"] = dec_key;
        json_data["lastKnownRevisionDate"] = utils::getBitwardenTime();

        Botan::secure_scrub_memory(dec_key.data(), dec_key.size());

        httplib::Result res = m_vault_client->Post("/api/ciphers/" + uuid + "/attachment/v2", headers, json_data.dump(), "application/json");

        lock.unlock();

        std::expected<void, NetworkError> err = getError_(res);

        if (!err.has_value()) {
            return std::unexpected(err.error());
        }

        if (!nlohmann::json::accept(res->body)) {
            return std::unexpected(NetworkError::Unknown);
        }

        nlohmann::json body = nlohmann::json::parse(res->body);

        if (!body.contains("cipherResponse") || !body.contains("attachmentId") ||
            !body["cipherResponse"].is_object() || !body["cipherResponse"].contains("attachments") ||
            !body["attachmentId"].is_string()) {
            return std::unexpected(NetworkError::Unknown);
        }

        std::string dec_contents = utils::getString(contents);

        httplib::UploadFormDataItems items = {
            {
                "data",
                dec_contents,
                dec_name,
                "application/octet-stream"
            }
        };

        Botan::secure_scrub_memory(dec_name.data(), dec_name.size());
        Botan::secure_scrub_memory(dec_contents.data(), dec_contents.size());

        std::string upload_url = "/api/ciphers/" + uuid + "/attachment/" + body["attachmentId"].get<std::string>();
        
        /**
         * @todo Double CHeck this
         */
        if (body.contains("fileUploadType") && body["fileUploadType"].is_number() &&
            body["fileUploadType"] == 1 && body.contains("url") && body["url"].is_string()) {
            upload_url = body["url"];
        }

        lock.lock();

        httplib::Result upload_res = m_vault_client->Post(upload_url, 
            headers, items, [&on_progress](uint64_t current, uint64_t total) -> bool {
                if (on_progress && total > 0) {
                    on_progress(static_cast<float>(current) / static_cast<float>(total));
                }
                return true;
            });

        lock.unlock();

        std::expected<void, NetworkError> upload_err = getError_(upload_res);

        if (!upload_err.has_value()) {
            return std::unexpected(upload_err.error());
        }

        return body;
    }
    
    std::expected<nlohmann::json, NetworkError> BitwardenNetwork::removeAttachment(const ItemId& uuid, 
        const Botan::secure_vector<uint8_t>& attachment_id) {
        if (!m_init_) {
            return std::unexpected(NetworkError::Uninitialised);
        }
        
        if (m_connectivity == Connectivity::Offline) {
            return std::unexpected(NetworkError::OfflineNetwork);
        }

        std::string access_token = getString(m_session.access_token);

        std::lock_guard<std::mutex> lock(m_vault_client_mutex_);
        httplib::Headers headers = {
            { "Authorization", "Bearer " + access_token },
            { "Content-Type", "application/json" },
            { "bitwarden-client-name", bitwarden_device_type },
            { "bitwarden-client-version", bitwarden_version },
        };

        Botan::secure_scrub_memory(access_token.data(), access_token.size());

        httplib::Result res = m_vault_client->Delete("/api/ciphers/" + uuid + "/attachment/" + utils::getString(attachment_id), headers);

        std::expected<void, NetworkError> err = getError_(res);

        if (!err.has_value()) {
            return std::unexpected(err.error());
        }

        if (!nlohmann::json::accept(res->body)) {
            return std::unexpected(NetworkError::Unknown);
        }

        return nlohmann::json::parse(res->body);
    }
    
    std::expected<nlohmann::json, NetworkError> BitwardenNetwork::downloadAttachment(const ItemId& uuid, 
        const Botan::secure_vector<uint8_t>& attachment_id, 
        std::function<void(float)> on_progress, 
        Botan::secure_vector<uint8_t>& o_data) {
        if (!m_init_) {
            return std::unexpected(NetworkError::Uninitialised);
        }
        
        if (m_connectivity == Connectivity::Offline) {
            return std::unexpected(NetworkError::OfflineNetwork);
        }

        std::string access_token = getString(m_session.access_token);

        std::unique_lock<std::mutex> lock(m_vault_client_mutex_);
        httplib::Headers headers = {
            { "Authorization", "Bearer " + access_token },
            { "Content-Type", "application/json" },
            { "bitwarden-client-name", bitwarden_device_type },
            { "bitwarden-client-version", bitwarden_version },
        };

        Botan::secure_scrub_memory(access_token.data(), access_token.size());

        httplib::Result res = m_vault_client->Get("/api/ciphers/" + uuid + "/attachment/" + utils::getString(attachment_id), headers);

        lock.unlock();

        std::expected<void, NetworkError> err = getError_(res);

        if (!err.has_value()) {
            return std::unexpected(err.error());
        }

        if (!nlohmann::json::accept(res->body)) {
            return std::unexpected(NetworkError::Unknown);
        }

        nlohmann::json body = nlohmann::json::parse(res->body);

        if (!body.contains("url") || !body["url"].is_string() ||
            !body.contains("fileName") || !body["fileName"].is_string() ||
            !body.contains("key") || !body["key"].is_string()) {
            return std::unexpected(NetworkError::Unknown);
        }

        boost::system::result<boost::urls::url_view> parsed = boost::urls::parse_uri(body["url"]);
        if (!parsed || parsed->scheme_id() != boost::urls::scheme::https) {
            return std::unexpected(NetworkError::Unknown);
        }

        std::string origin = std::string(parsed->scheme()) + "://" + std::string(parsed->encoded_host());
        if (parsed->has_port()) {
            origin += ":" + std::string(parsed->port());
        }

        std::string path = std::string(parsed->encoded_target());
        if (path.empty()) {
            path = "/";
        }

        httplib::Client download_client(origin);
        download_client.set_follow_location(true);
        download_client.set_connection_timeout(10);
        download_client.set_read_timeout(60);

        httplib::Headers download_headers;

        o_data.clear();

        httplib::Result download_res = download_client.Get(path, download_headers,
            [&o_data](const httplib::Response& response) {
                if (response.status != 200) {
                    return false;
                }
                if (response.has_header("Content-Length")) {
                    try {
                        o_data.reserve(std::stoull(response.get_header_value("Content-Length")));
                    } catch (...) {
                        return false;
                    }
                }
                return true;
            },
            [&o_data](const char* data, size_t length) {
                const uint8_t* c_data = reinterpret_cast<const uint8_t*>(data);
                o_data.insert(o_data.end(), c_data, c_data + length);
                return true;
            },
            [&on_progress](uint64_t current, uint64_t total) -> bool {
                if (on_progress && total > 0) {
                    on_progress(static_cast<float>(current) / static_cast<float>(total));
                }
                return true;
            });

        std::expected<void, NetworkError> download_err = getError_(download_res);

        if (!download_err.has_value()) {
            return std::unexpected(download_err.error());
        }

        if (o_data.size() < 1 + 16 + 32 + 1) {
            logger->error("Blob too short after decode: {}", o_data.size());
            return std::unexpected(NetworkError::Unknown);
        } else if (o_data[0] != 0x02) {
            logger->error("Unexpected enc type: 0x{:02x}", o_data[0]);
            return std::unexpected(NetworkError::Unknown);
        }

        return body;
    }
    
    std::expected<Botan::secure_vector<uint8_t>, NetworkError> BitwardenNetwork::downloadIcon(
        const Botan::secure_vector<uint8_t>& url) {
        if (!m_init_) {
            return std::unexpected(NetworkError::Uninitialised);
        }
        
        if (m_connectivity == Connectivity::Offline) {
            return std::unexpected(NetworkError::OfflineNetwork);
        }

        std::string uri = utils::getString(url);
        if (url.starts_with("https://")) {
            uri = url.substr(8);
        } else if (url.starts_with("http://")) {
            uri = url.substr(7);
        }

        std::lock_guard<std::mutex> lock(m_icon_client_mutex_);

        httplib::Result res = m_icon_client->Get("/" + uri + "/icon.png");

        std::expected<void, NetworkError> err = getError_(res);

        if (!err.has_value()) {
            return std::unexpected(err.error());
        }

        return Botan::secure_vector<uint8_t>(res->body.begin(), res->body.end());
    }
    
    std::expected<nlohmann::json, NetworkError> BitwardenNetwork::getVault() {
        if (!m_init_) {
            return std::unexpected(NetworkError::Uninitialised);
        }
        
        if (m_connectivity == Connectivity::Offline) {
            return std::unexpected(NetworkError::OfflineNetwork);
        }

        std::string access_token = getString(m_session.access_token);

        std::lock_guard<std::mutex> lock(m_vault_client_mutex_);
        httplib::Headers headers = {
            { "Authorization", "Bearer " + access_token },
            { "Content-Type", "application/json" },
            { "bitwarden-client-name", bitwarden_device_type },
            { "bitwarden-client-version", bitwarden_version },
        };

        Botan::secure_scrub_memory(access_token.data(), access_token.size());

        httplib::Result res = m_vault_client->Get("/api/sync", headers);

        std::expected<void, NetworkError> err = getError_(res);

        if (!err.has_value()) {
            return std::unexpected(err.error());
        }

        if (!nlohmann::json::accept(res->body)) {
            return std::unexpected(NetworkError::Unknown);
        }

        return nlohmann::json::parse(res->body);
    }
    
    std::expected<nlohmann::json, NetworkError> BitwardenNetwork::getVersion() {
        if (!m_init_) {
            return std::unexpected(NetworkError::Uninitialised);
        }
        
        if (m_connectivity == Connectivity::Offline) {
            return std::unexpected(NetworkError::OfflineNetwork);
        }

        std::string access_token = getString(m_session.access_token);

        std::lock_guard<std::mutex> lock(m_vault_client_mutex_);
        httplib::Headers headers = {
            { "Authorization", "Bearer " + access_token },
            { "Content-Type", "application/json" },
            { "bitwarden-client-name", bitwarden_device_type },
            { "bitwarden-client-version", bitwarden_version },
        };

        Botan::secure_scrub_memory(access_token.data(), access_token.size());

        httplib::Result res = m_vault_client->Get("/api/sync", headers);

        std::expected<void, NetworkError> err = getError_(res);

        if (!err.has_value()) {
            return std::unexpected(err.error());
        }

        if (!nlohmann::json::accept(res->body)) {
            return std::unexpected(NetworkError::Unknown);
        }

        return nlohmann::json::parse(res->body);
    }
    
    std::expected<Profile, NetworkError> BitwardenNetwork::getProfile() {
        if (!m_init_) {
            return std::unexpected(NetworkError::Uninitialised);
        }
        
        if (m_connectivity == Connectivity::Offline) {
            return std::unexpected(NetworkError::OfflineNetwork);
        }

        std::string access_token = getString(m_session.access_token);

        std::lock_guard<std::mutex> lock(m_vault_client_mutex_);
        httplib::Headers headers = {
            { "Authorization", "Bearer " + access_token },
        };

        Botan::secure_scrub_memory(access_token.data(), access_token.size());

        httplib::Result res = m_vault_client->Get("/api/accounts/profile", headers);

        std::expected<void, NetworkError> err = getError_(res);

        if (!err.has_value()) {
            return std::unexpected(err.error());
        }

        if (!nlohmann::json::accept(res->body)) {
            return std::unexpected(NetworkError::Unknown);
        }

        return nlohmann::json::parse(res->body);
    }
    
    Connectivity BitwardenNetwork::getConnectivity() {
        if (!m_init_) {
            return std::unexpected(NetworkError::Uninitialised);
        }

        std::lock_guard<std::mutex> lock(m_api_client_mutex_);
        m_api_client->set_connection_timeout(1);

        httplib::Result res = m_api_client->Get("/alive");

        if (res && res->status == 200) {
            m_connectivity = VaultConnectivity::Online;
        } else {
            m_connectivity = VaultConnectivity::Offline;
        }

        return m_connectivity;
    }
    
    NetworkError BitwardenNetwork::checkAccessTokenValidity() {
        if (!m_init_) {
            return NetworkError::Uninitialised;
        }
        
        if (m_connectivity == Connectivity::Offline) {
            return NetworkError::OfflineNetwork;
        }

        std::lock_guard<std::mutex> lock(m_api_client_mutex_);
        m_api_client->set_connection_timeout(3);

        httplib::Headers headers = {
            {"Authorization", "Bearer " + accessString}
        };

        httplib::Result res = m_api_client->Get("/api/accounts/profile", headers);

        if (!err.has_value()) {
            return err.error();
        }

        return NetworkError::Success;
    }
    
    std::expected<nlohmann::json, NetworkError> BitwardenNetwork::refreshToken() {
        if (!m_init_) {
            return std::unexpected(NetworkError::Uninitialised);
        }
        
        if (m_connectivity == Connectivity::Offline) {
            return std::unexpected(NetworkError::OfflineNetwork);
        }

        std::lock_guard<std::mutex> lock(m_vault_client_mutex_);

        httplib::Params data;
        data.emplace("grant_type", "refresh_token");
        data.emplace("deviceType", bitwarden_device_type);
        data.emplace("refresh_token", refreshToken);

        httplib::Result res = m_vault_client->Post("/identity/connect/token", data);

        std::expected<void, NetworkError> err = getError_(res);

        if (!err.has_value()) {
            return std::unexpected(err.error());
        }

        if (!nlohmann::json::accept(res->body)) {
            return std::unexpected(NetworkError::Unknown);
        }

        return nlohmann::json::parse(res->body);
    }
    
    NetworkError BitwardenNetwork::listen(std::function<void(NetworkEvent)> on_event) {
        
    }
    
    bool BitwardenNetwork::stopListening() {
        
    }
    
    NetworkError BitwardenNetwork::startTokenRefreshThread() {
        
    }
    
    bool BitwardenNetwork::stopTokenRefreshThread() {
        
    }
    
    Vendor BitwardenNetwork::getVendor() {
        return Vendor::BitWarden;
    }
    
    std::expected<TokenResult, NetworkError> BitwardenNetwork::getToken_(const httplib::Params& data) {
        std::lock_guard<std::mutex> lock(m_vault_client_mutex_);

        m_vault_client_->set_default_headers({
            { "Accept", "application/json" },
            { "Content-Type", "application/x-www-form-urlencoded; charset=utf-8" },
            { "bitwarden-client-name", bitwarden_device_type },
            { "bitwarden-client-version", bitwarden_version },
        });

        std::string str_email(email.begin(), email.end());
        std::string str_master_password_hash(master_password_hash.begin(), master_password_hash.end());
        
        httplib::Result res = m_vault_client_->Post("/identity/connect/token", data);

        std::expected<void, NetworkError> err = getError_(res);

        if (!err.has_value()) {
            return std::unexpected(err.error());
        }

        if (!nlohmann::json::accept(res->body)) {
            return std::unexpected(NetworkError::Invalid);
        }

        nlohmann::json body = nlohmann::json::parse(res->body);

        if (res->status == 400) {
            if (!body.contains("error") || !body.contains("error_description") || 
                !body.contains("TwoFactorProviders") || !body["TwoFactorProviders"].is_array() || 
                !body.contains("TwoFactorProviders2") || body["error"] != "invalid_grant" || 
                body["error_description"] != "Two factor required.") {
                return std::unexpected(NetworkError::Invalid);
            }

            MultiFactorChallenge challenge;
            challenge.raw = body;

            for (const nlohmann::json& item : body["TwoFactorProviders"]) {
                if (!item.is_string()) {
                    continue;
                }

                /**
                 * @note help from claude.
                 */
                std::string str_item = item.get<std::string>();
                int value{};
                std::from_chars_result num_value = 
                    std::from_chars(str_item.data(), str_item.data() + str_item.size(), value);

                if (!num_value || num_value.ptr != str_item.data() + str_item.size()) {
                    continue;
                }

                if (value < 0 || value > 8) {
                    continue;
                }

                /**
                 * @note human intelligence
                 */
                TwoFactorProviderType provider = static_cast<TwoFactorProviderType>(value);

                challenge.available_methods.push_back(toMultiFactorAuth(provider));
            }

            return challenge;
        }

        if (!body.contains("access_token") || !body.contains("refresh_token") ||
            !body.contains("expires_in") || !body["access_token"].is_string() ||
            !body["refresh_token"].is_string() || !body["expires_in"].is_number()) {
            return std::unexpected(NetworkError::Invalid);
        }

        std::string access_token = body["access_token"].get<std::string>();
        std::string refresh_token = body["refresh_token"].get<std::string>();

        AuthResult auth_result;
        auth_result.session.access_token = 
            Botan::secure_vector<uint8_t>(access_token.begin(), access_token.end());
        auth_result.session.refresh_token = 
            Botan::secure_vector<uint8_t>(refresh_token.begin(), refresh_token.end());
        auth_result.session.expires_in = body["expires_in"].get<int>();
        auth_result.raw = body;

        return auth_result;
    }

    std::expected<void, NetworkError> BitwardenNetwork::getError_(const httplib::Result& res) {
        if (!res) {
            logger->error("request failed");
            return std::unexpected(NetworkError::Unknown);
        }
        if (res->status == 401) {
            logger->error("failed: unauthorised");
            return std::unexpected(NetworkError::Unauthorised);
        } else if (res->status == 429) {
            logger->error("failed: rate limited");
            return std::unexpected(NetworkError::RateLimited);
        } else if (res->status >= 500) {
            logger->error("failed: server error");
            return std::unexpected(NetworkError::ServerError);
        } else if (res->status != 200) {
            logger->error("failed: {}", res->status);
            return std::unexpected(NetworkError::Unknown);
        }

        return {};
    }
}