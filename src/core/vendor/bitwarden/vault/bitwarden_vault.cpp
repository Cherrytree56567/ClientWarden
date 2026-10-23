#include "bitwarden_vault.h"

namespace clientwarden::vendor::bitwarden {
    BitWardenVault::BitWardenVault(ItemId uuid) : Vault(uuid) {

    }

    BitWardenVault::~BitWardenVault() {
        
    }

    LoginResult BitWardenVault::login(Credential cred) {
        PasswordCredential credential;

        if (std::holds_alternative<PasswordCredential>(cred)) {
            credential = std::get<PasswordCredential>(cred);

            std::expected<PreLoginResult, NetworkError> pre_login_res = 
                m_network->preLogin(credential.m_email);
            
            if (!pre_login_res.has_value()) {
                return AuthResult::InvalidCreds;
            }

            std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> internal_key = 
                m_crypto->makeInternalKey(credential.m_password, credential.m_email,
                pre_login_res.value().params);
            
            if (!internal_key.has_value()) {
                return AuthResult::InvalidCreds;
            }

            std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> hashed_password = 
                m_crypto->hashedPassword(credential.m_password, internal_key.value());
            
            if (!hashed_password.has_value()) {
                return AuthResult::InvalidCreds;
            }

            AuthKeys keys;
            keys.internal_key = std::move(internal_key.value());
            keys.master_password_hash = std::move(hashed_password.value());

            CryptoErrors keys_err = m_crypto->setAuthKeys(keys);

            if (keys_err != CryptoErrors::Success) {
                return AuthResult::CryptoError;
            }
        } else if (std::holds_alternative<MultiFactorProof>(cred) && m_password_cred_set_) {
            credential = m_password_cred_;
        } else {
            return AuthResult::InvalidParams;
        }

        std::expected<AuthKeys, CryptoErrors> auth_keys = 
            m_crypto->getKeys();
        
        if (!auth_keys.has_value()) {
            return AuthResult::CryptoError;
        }

        std::expected<TokenResult, NetworkError> token;
        
        if (std::holds_alternative<PasswordCredential>(cred)) {
            token = m_network->getToken(credential.m_email, 
                auth_keys.value().master_password_hash);
        } else if (std::holds_alternative<MultiFactorProof>(cred)) {
            token = m_network->getToken2FA(credential.m_email, 
                auth_keys.value().master_password_hash, std::get<MultiFactorProof>(cred));
        }
            
        if (!token.has_value()) {
            return AuthResult::NetworkError;
        }

        if (std::holds_alternative<vault::AuthResult>(token.value())) {
            vault::AuthResult auth_result = std::get<vault::AuthResult>(token.value());

            m_network->setSession(auth_result.session);

            std::expected<void, SettingsError> keychain_err = 
                m_settings->keychainSet(KeychainSecurity::Sensitive, "access_token", 
                auth_result.session.access_token);
                
            if (!keychain_err.has_value()) {
                return AuthResult::KeychainError;
            }

            keychain_err = m_settings->keychainSet(KeychainSecurity::Sensitive, 
                "refresh_token", auth_result.session.refresh_token);
                
            if (!keychain_err.has_value()) {
                return AuthResult::KeychainError;
            }

            keychain_err = m_settings->keychainSet(KeychainSecurity::Secure, 
                "expires_at", utils::getSecureVector(auth_result.session.expires_at));
                
            if (!keychain_err.has_value()) {
                return AuthResult::KeychainError;
            }

            std::expected<bool, SyncError> sync_err = m_sync->fullSync();

            if (!sync_err.has_value() || (sync_err.has_value() && !sync_err.value())) {
                return AuthResult::SyncError;
            }

            RuntimeError run_err = m_runtime->loadVault();

            if (run_err != RuntimeError::Success) {
                return AuthResult::RuntimeError;
            }

            std::expected<Profile, RuntimeError> profile_err = 
                m_runtime->getProfile();
                
            if (!profile_err.has_value()) {
                return AuthResult::RuntimeError;
            }

            if (!profile_err.value().raw.contains("key") ||
                !profile_err.value().raw["key"].is_string()) {
                return AuthResult::InvalidVault;
            }

            CryptoErrors keys_err =
                m_crypto->setVaultKeys(utils::getSecureVector(profile_err.value().raw["key"]));
                
            if (keys_err != CryptoErrors::Success) {
                return AuthResult::CryptoError;
            }

            m_network->startTokenRefreshThread();
            m_network->startConnectivityThread();

            /**
             * @brief Check if its a Classic or WebSocket Sync and handle accordingly.
             */
            SyncMethod sync_method = m_settings->getSyncMethod();

            if (sync_method == SyncMethod::Classic) {
                m_runtime->startSyncThread();
            } else if (sync_method == SyncMethod::WebSocket) {
                m_network->listen();
            }

            if (m_password_cred_set_) {
                m_password_cred_.clear();
            }

            return AuthResult::Success;
        } else if (std::holds_alternative<MultiFactorChallenge>(token.value())) {
            m_password_cred_ = credential;
            m_password_cred_set_ = true;

            return std::get<MultiFactorChallenge>(token.value());
        } else {
            return AuthResult::Failed;
        }
    }

    AuthResult BitWardenVault::signup(SignupCredential cred) {
        
    }

    AuthResult BitWardenVault::unlock(UnlockCredential cred) {
        
    }

    bool BitWardenVault::lock() {
        
    }

    bool BitWardenVault::logout() {
        
    }

    bool BitWardenVault::setupBiometricUnlock(UnlockType type) {
        
    }

    bool BitWardenVault::checkReprompt(Botan::secure_vector<uint8_t> password) {
        
    }
        
    std::shared_ptr<GenericItem> BitWardenVault::getItem(ItemId uuid) {
        
    }

    std::shared_ptr<Folder> BitWardenVault::getFolder(ItemId uuid) {
        
    }
    
    std::shared_ptr<Folder> BitWardenVault::createFolder() {
        
    }
    
    std::shared_ptr<CipherQuery> BitWardenVault::getCipherQuery() {
        
    }

    Vendor getVendor() {
        
    }
}