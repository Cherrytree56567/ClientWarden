#pragma once
#include "vault/vault.h"

namespace clientwarden::vendor::bitwarden {
    class BitWardenVault : public Vault {
    public:
        explicit BitWardenVault(ItemId uuid);
        ~BitWardenVault() override;

        LoginResult login(Credential cred) override;
        AuthResult signup(SignupCredential cred) override;
        AuthResult unlock(UnlockCredential cred) override;
        bool lock() override;
        bool logout() override;

        bool setupBiometricUnlock(UnlockType type) override;

        bool checkReprompt(Botan::secure_vector<uint8_t> password) override;
        
        std::shared_ptr<GenericItem> getItem(ItemId uuid) override;
        std::shared_ptr<Folder> getFolder(ItemId uuid) override;
        std::shared_ptr<Folder> createFolder() override;
        std::shared_ptr<CipherQuery> getCipherQuery() override;

        Vendor getVendor() override;
    };
}