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

            /**
             * @note We don't need to store the KDF Params bc it should be in the vault.
             */
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
                m_password_cred_set_ = false;
            }

            return AuthResult::Success;
        } else if (std::holds_alternative<MultiFactorChallenge>(token.value())) {
            m_password_cred_.email = credential.email;
            m_password_cred_set_ = true;

            return std::get<MultiFactorChallenge>(token.value());
        } else {
            return AuthResult::Failed;
        }
    }

    AuthResult BitWardenVault::signup(SignupCredential cred) {
        return AuthResult::Unimplemented;
    }

    AuthResult BitWardenVault::unlock(UnlockCredential cred) {
        if (std::holds_alternative<UnlockPasswordCredential>(cred)) {
            UnlockPasswordCredential credential = std::get<UnlockPasswordCredential>(cred);

            /**
             * @todo Load Vault
             */
            RuntimeError vault_err = m_runtime->loadVault();

            if (vault_err != RuntimeError::Success) {
                return AuthResult::InvalidVault;
            }

            /**
             * @todo Get Vault KDF Info
             */
            std::expected<nlohmann::json, RuntimeError> vault_info_err = 
                m_runtime->getVaultInfo();
            
            if (!vault_info.has_value()) {
                return AuthResult::InvalidVault;
            }

            nlohmann::json vault_info = vault_info_err.value();

            /**
             * @note Huge Block!
             */
            if (!vault_info.contains("masterPasswordUnlock") ||
                !vault_info["masterPasswordUnlock"].is_object() ||
                !vault_info["masterPasswordUnlock"].contains("kdf") ||
                !vault_info["masterPasswordUnlock"]["kdf"].is_object() ||
                !vault_info["masterPasswordUnlock"]["kdf"].contains("iterations") ||
                !vault_info["masterPasswordUnlock"]["kdf"]["iterations"].is_number_integer() ||
                !vault_info["masterPasswordUnlock"]["kdf"].contains("kdfType") ||
                !vault_info["masterPasswordUnlock"]["kdf"]["kdfType"].is_number_integer() ||
                !vault_info["masterPasswordUnlock"].contains("salt") ||
                !vault_info["masterPasswordUnlock"]["salt"].is_string()) {
                return AuthResult::InvalidVault;
            }

            std::string salt = vault_info["masterPasswordUnlock"]["salt"];

            KDFParams kdf_params;
            kdf_params.type = static_cast<KDFType>(
                vault_info["masterPasswordUnlock"]["kdf"]["kdfType"]);
            kdf_params.iterations = vault_info["masterPasswordUnlock"]["kdf"]["iterations"];

            if (kdf_params.type == KDFType::Argon2ID) {
                /**
                 * @todo TESTING - Check if memory is in KiB or MiB
                 */
                if (!vault_info["masterPasswordUnlock"]["kdf"].contains("memory") ||
                    !vault_info["masterPasswordUnlock"]["kdf"]["memory"].is_number_integer() ||
                    !vault_info["masterPasswordUnlock"]["kdf"].contains("parallelism") ||
                    !vault_info["masterPasswordUnlock"]["kdf"]["parallelism"].is_number_integer()) {
                    return AuthResult::InvalidVault;
                }

                kdf_params.memory = vault_info["masterPasswordUnlock"]["kdf"]["memory"];
                kdf_params.parallelism = vault_info["masterPasswordUnlock"]["kdf"]["parallelism"];
            }

            /**
             * @todo Get AuthSession
             */
            AuthSession session;

            std::expected<Botan::secure_vector<uint8_t>, SettingsError> keychainGet(const std::string& name)
        }
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