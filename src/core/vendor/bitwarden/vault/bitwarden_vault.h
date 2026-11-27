#pragma once
#include "vault/vault.h"
#include "bitwarden_autofill/bitwarden_autofill.h"
#include "bitwarden_crypto/bitwarden_crypto.h"
#include "bitwarden_network/bitwarden_network.h"
#include "bitwarden_orchestrator/bitwarden_orchestrator.h"
#include "bitwarden_runtime/bitwarden_runtime.h"
#include "bitwarden_sync/bitwarden_sync.h"
#include "bitwarden_versioning/bitwarden_versioning.h"
#include "../bitwarden_items/bitwarden_generic_item.h"
#include "../bitwarden_folder/bitwarden_folder.h"
#include "../bitwarden_query/bitwarden_query.h"

namespace clientwarden::vendor::bitwarden {
    using namespace ::clientwarden::vault;
    using namespace ::clientwarden::platforms;
    using namespace ::clientwarden::vendor::bitwarden::vault;
    
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

        std::expected<bool, AuthResult> checkReprompt(
            Botan::secure_vector<uint8_t> password) override;
        
        std::shared_ptr<GenericItem> getItem(ItemId uuid) override;
        std::shared_ptr<Folder> getFolder(ItemId uuid) override;
        std::shared_ptr<Folder> createFolder() override;
        std::shared_ptr<Query> getQuery() override;

        Vendor getVendor() override;
    private:
        void onNetworkEvent_(NetworkEvent event);

        PasswordCredential m_password_cred_;
        bool m_password_cred_set_ = false;
    };
}