#include "bitwarden_vault.h"

namespace clientwarden::vendor::bitwarden {
    BitWardenVault::BitWardenVault(ItemId uuid) : Vault(uuid) {

    }

    BitWardenVault::~BitWardenVault() {
        
    }

    LoginResult BitWardenVault::login(Credential cred) {
        
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