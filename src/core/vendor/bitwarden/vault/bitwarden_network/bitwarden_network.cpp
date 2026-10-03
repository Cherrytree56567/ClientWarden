#include "bitwarden_network.h"

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

        for (Botan::secure_vector<uint8_t> url : urls) {
            boost::system::result<boost::urls::url_view> url_parse = 
                boost::urls::parse_uri(std::string(url.begin(), url.end()));
            
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

        std::lock_guard<std::mutex> lock(m_vault_client_mutex_);

        httplib::Headers headers = {
            { "Content-Type", "application/json" },
            { "bitwarden-client-name", app_type },
            { "bitwarden-client-version", bitwarden_version },
        };

        nlohmann::json payload;
        payload["email"] = std::string(email.begin(), email.end());

        httplib::Result res = m_vault_client_->Post("/identity/accounts/prelogin", headers, 
            payload.dump(), "application/json");

        if (!res) {
            logger->error("preLogin request failed");
            return std::unexpected(NetworkError::Invalid);
        }
        if (res->status != 200) {
            logger->error("preLogin failed: {}", res->status);
            return std::unexpected(NetworkError::ServerError);
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
        
    }
    
    std::expected<TokenResult, NetworkError> BitwardenNetwork::getToken2FA(const Botan::secure_vector<uint8_t>& email, 
        const Botan::secure_vector<uint8_t>& master_password_hash, const MultiFactorProof& proof) {
        
    }
    
    std::expected<nlohmann::json, NetworkError> BitwardenNetwork::newItem(const nlohmann::json& data) {
        
    }
    
    std::expected<nlohmann::json, NetworkError> BitwardenNetwork::updateItem(const ItemId& uuid, 
        const nlohmann::json& data) {
        
    }
    
    std::expected<nlohmann::json, NetworkError> BitwardenNetwork::deleteItem(const ItemId& uuid) {
        
    }
    
    std::expected<nlohmann::json, NetworkError> BitwardenNetwork::softDeleteItem(const ItemId& uuid) {
        
    }
    
    std::expected<nlohmann::json, NetworkError> BitwardenNetwork::restoreItem(const ItemId& uuid) {
        
    }
    
    std::expected<nlohmann::json, NetworkError> BitwardenNetwork::archiveItem(const ItemId& uuid) {
        
    }
    
    std::expected<nlohmann::json, NetworkError> BitwardenNetwork::unArchiveItem(const ItemId& uuid) {
        
    }
    
    std::expected<nlohmann::json, NetworkError> BitwardenNetwork::createFolder(const Botan::secure_vector<uint8_t>& name) {
        
    }
    
    std::expected<nlohmann::json, NetworkError> BitwardenNetwork::renameFolder(const ItemId& uuid, 
        const Botan::secure_vector<uint8_t>& name) {
        
    }
    
    std::expected<nlohmann::json, NetworkError> BitwardenNetwork::deleteFolder(const ItemId& uuid) {
        
    }
    
    std::expected<nlohmann::json, NetworkError> BitwardenNetwork::addAttachment(const ItemId& uuid, 
        const Botan::secure_vector<uint8_t>& name, const Botan::secure_vector<uint8_t>& contents,
        const Botan::secure_vector<uint8_t>& key, std::function<void(float)> on_progress) {
        
    }
    
    std::expected<nlohmann::json, NetworkError> BitwardenNetwork::removeAttachment(const ItemId& uuid, 
        const Botan::secure_vector<uint8_t>& attachment_id) {
        
    }
    
    std::expected<nlohmann::json, NetworkError> BitwardenNetwork::downloadAttachment(const ItemId& uuid, 
        const Botan::secure_vector<uint8_t>& attachment_id, 
        std::function<void(float)> on_progress, 
        const Botan::secure_vector<uint8_t>& o_data) {
        
    }
    
    std::expected<Botan::secure_vector<uint8_t>, NetworkError> BitwardenNetwork::downloadIcon(
        const Botan::secure_vector<uint8_t>& url) {
        
    }
    
    std::expected<nlohmann::json, NetworkError> BitwardenNetwork::getVault() {
        
    }
    
    std::expected<nlohmann::json, NetworkError> BitwardenNetwork::getVersion() {
        
    }
    
    std::expected<Profile, NetworkError> BitwardenNetwork::getProfile() {
        
    }
    
    Connectivity BitwardenNetwork::getConnectivity() {
        
    }
    
    NetworkError BitwardenNetwork::checkAccessTokenValidity() {
        
    }
    
    std::expected<nlohmann::json, NetworkError> BitwardenNetwork::refreshToken() {
        
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
}