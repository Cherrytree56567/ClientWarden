#include "bitwarden_vault.h"

namespace clientwarden::vendor::bitwarden {
    BitWardenVault::BitWardenVault(ItemId uuid) : Vault(uuid) {

    }

    BitWardenVault::~BitWardenVault() {
        
    }

    LoginResult BitWardenVault::login(Credential cred) {
        if (std::holds_alternative<PasswordCredential>(cred)) {
            PasswordCredential credential = std::get<PasswordCredential>(cred);

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
                m_crypto->hashedPassword()

            AuthKeys keys;
            keys.internal_key = std::move(internal_key.value());
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