#include "vault_manager.h"

namespace clientwarden {
    VaultManager::VaultManager() {
        if (!loadVaults()) {
            createVaultData();
        }

        if (!g_logger) {
            spdlog::set_pattern("[%H:%M:%S] [%n] [%^---%L---%$] [thread %t] %v");

            std::shared_ptr<spdlog::sinks::stdout_color_sink_mt> console_sink = 
                std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
            std::shared_ptr<spdlog::sinks::basic_file_sink_mt> file_sink = 
                std::make_shared<spdlog::sinks::basic_file_sink_mt>(m_storage_.path.string() + "/cw.log", true);

            g_logger = std::make_shared<spdlog::logger>("ClientWarden", spdlog::sinks_init_list{console_sink, file_sink});
            g_logger->set_level(spdlog::level::trace);
            g_logger->flush_on(spdlog::level::trace);
            spdlog::register_logger(g_logger);
        }
    }

    VaultManager::~VaultManager() {
        lockAll();
    }

    VaultManager& VaultManager::instance() {
        static VaultManager inst;
        return inst;
    }

    ItemId VaultManager::getMainVault() {
        return m_main_vault_;
    }

    std::expected<std::shared_ptr<Vault>, VaultManagerError> VaultManager::getVault(ItemId uuid) {
        if (m_vaults_.contains(uuid)) {
            return m_vaults_.at(uuid);
        }

        return std::unexpected(VaultManagerError::NotFound);
    }

    Botan::secure_vector<ItemId> VaultManager::getVaultUUIDs() {
        Botan::secure_vector<ItemId> result;
        result.reserve(m_vaults_.size());

        for (const auto& [id, vault] : m_vaults_) {
            result.push_back(id);
        }

        return result;
    }

    size_t VaultManager::getVaultCount() {
        return m_vaults_.size();
    }

    bool VaultManager::vaultExists(ItemId uuid) {
        return m_vaults_.contains(uuid);
    }
    
    std::expected<LoginResult, VaultManagerError> VaultManager::login(Credential cred, Vendor vendor, ItemId& o_id) {
        o_id = utils::getUniqueId();

        std::shared_ptr<Vault> vault = createVault(vendor, o_id);

        LoginResult result = vault->login(cred);

        if (std::holds_alternative<AuthResult>(result)) {
            if (std::get<AuthResult>(result) == AuthResult::Success) {
                m_vaults_[o_id] = vault;

                saveVault(vendor, o_id);
                
                return result;
            }
        } else if (std::holds_alternative<vault::MultiFactorChallenge>(result)) {
            m_pending_vaults_[o_id] = vault;
            
            return result;
        }

        return std::unexpected(VaultManagerError::Unknown);
    }

    std::expected<LoginResult, VaultManagerError> VaultManager::continueLogin(Credential cred, ItemId id) {
        if (!m_pending_vaults_.contains(id)) {
            return std::unexpected(VaultManagerError::NotFound);
        }
        
        std::shared_ptr<Vault> vault = m_pending_vaults_.at(uuid);

        LoginResult result = vault->login(cred);

        if (std::holds_alternative<AuthResult>(result)) {
            if (std::get<AuthResult>(result) == AuthResult::Success) {
                m_vaults_[vault_id] = vault;
                m_pending_vaults_.erase(id);

                saveVault(vault.getVendor(), id);
                
                return result;
            }
        } else if (std::holds_alternative<vault::MultiFactorChallenge>(result)) {
            return result;
        }

        return std::unexpected(VaultManagerError::Unknown);
    }

    std::expected<AuthResult, VaultManagerError> VaultManager::signup(SignupCredential cred, Vendor vendor, ItemId& o_id) {
        o_id = utils::getUniqueId();

        std::shared_ptr<Vault> vault = createVault(vendor, o_id);

        AuthResult result = vault->signup(cred);

        if (result == AuthResult::Success) {
            m_vaults_[o_id] = vault;
            
            saveVault(vendor, o_id);

            return result;
        }

        return std::unexpected(VaultManagerError::Unknown);
    }

    bool VaultManager::logout(ItemId uuid) {
        if (m_vaults_.contains(uuid)) {
            bool result = m_vaults_.at(uuid).logout();

            if (result) {
                removeVault(uuid);
            }

            return result;
        }

        return false;
    }

    bool VaultManager::lock(ItemId uuid) {
        if (m_vaults_.contains(uuid)) {
            return m_vaults_.at(uuid).lock();
        }

        return false;
    }

    bool VaultManager::logoutAll() {
        bool result = true;

        for (const auto& [id, vault] : m_vaults_) {
            if (!logout(id)) {
                result = false;
            }
        }

        return result;
    }

    bool VaultManager::lockAll() {
        bool result = true;

        for (const auto& [id, vault] : m_vaults_) {
            if (!lock(id)) {
                result = false;
            }
        }

        return result;
    }

    bool VaultManager::loadVaults() {
        if (!m_storage_.exists()) {
            return false;
        }

        std::string vault_mgr_string = m_storage_.read("clientwarden.json");

        if (!nlohmann::json::accept(vault_mgr_string)) {
            return false;
        }

        m_data_ = nlohmann::json::parse(vault_mgr_string);

        if (!m_data_.contains("main_vault") || !m_data_.contains("vaults") || 
            !m_data_["vaults"].is_array()) {
            return false;
        }

        m_main_vault_ = m_data_["main_vault"];

        for (nlohmann::json vault : m_data_["vaults"]) {
            if (!vault.contains("id") || !vault.contains("vendor") ||
                !vault["id"].is_string() || !vault["vendor"].is_string()) {
                continue;
            }

            Vendor vendor = getVendor(vault["vendor"]);
            ItemId id = vault["id"];

            std::shared_ptr<Vault> local_vault = createVault(vendor, id);

            m_vaults_[id] = local_vault;
        }

        return true;
    }

    Vendor VaultManager::getVendor(std::string vendor) {
        if (vendor == "BitWarden") {
            return Vendor::BitWarden;
        }
    }
    
    std::string VaultManager::getVendorString(Vendor vendor) {
        if (vendor == Vendor::BitWarden) {
            return "BitWarden";
        }

        return "None";
    }

    bool VaultManager::saveVault(Vendor vendor, ItemId id) {
        nlohmann::json vault_data;
        vault_data["vendor"] = getVendorString(vendor);
        vault_data["id"] = id;

        if (!m_data_.contains("vaults") || !m_data_["vaults"].is_array()) {
            return false;
        }

        m_data_["vaults"].push_back(vault_data);

        m_storage_.write("clientwarden.json", m_data_.dump(4));

        return true;
    }

    bool VaultManager::removeVault(ItemId id) {
        if (!m_data_.contains("main_vault") || !m_data_.contains("vaults") || 
            !m_data_["vaults"].is_array()) {
            return false;
        }

        nlohmann::json& vaults = m_data_["vaults"];

        nlohmann::json::iterator iterator = std::ranges::find_if(vaults, [&](const nlohmann::json& entry) {
            return entry.value("id", std::string{}) == id;
        });

        if (iterator == vaults.end()) {
            return false;
        }

        vaults.erase(iterator);

        if (m_data_["main_vault"].is_string() && m_data_["main_vault"] == id) {
            m_data_["main_vault"] = nullptr;
        }

        m_storage_.write("clientwarden.json", m_data_.dump(4));

        return true;
    }

    bool VaultManager::createVaultData() {
        m_data_["main_vault"] = nullptr;
        m_data_["vaults"] = nlohmann::json::array();

        m_storage_.write("clientwarden.json", m_data_.dump(4));

        return true;
    }

    std::shared_ptr<Vault> VaultManager::createVault(Vendor vendor, ItemId id) {
        if (vendor == Vendor::BitWarden) {
            /**
             * TODO: todo
             */
            return std::make_shared<Vault>(id);
        }
        
        return std::make_shared<Vault>(id);
    }
}