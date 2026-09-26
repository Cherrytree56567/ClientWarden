#pragma once
#include <map>
#include <memory>
#include <optional>
#include <botan/secmem.h>
#include "vault/vault.h"

namespace clientwarden {
    enum class VaultManagerError {
        NotFound, 
        Unknown
    };
    
    /*
     * @brief Holds and manages multiple vaults
    */
    class VaultManager {
    public:
        VaultManager();
        ~VaultManager();

        VaultManager& instance();

        ItemId getMainVault();
        std::expected<std::shared_ptr<Vault>, VaultManagerError> getVault(ItemId uuid);
        Botan::secure_vector<ItemId> getVaultUUIDs();

        size_t getVaultCount();
        bool vaultExists(ItemId uuid);

        std::expected<LoginResult, VaultManagerError> login(Credential cred, Vendor vendor, ItemId& o_id);
        std::expected<AuthResult, VaultManagerError> continueLogin(Credential cred, ItemId id);
        std::expected<AuthResult, VaultManagerError> signup(SignupCredential cred, Vendor vendor, ItemId& o_id);
        /**
         * @brief Runs logout() on the vault, removes it from the vault map and the local db.
         */
        bool logout(ItemId uuid);
        bool lock(ItemId uuid);

        bool logoutAll();
        bool lockAll();
    
    private:
        bool loadVaults();
        Vendor getVendor(std::string vendor);
        std::string getVendorString(Vendor vendor);
        bool saveVault(Vendor vendor, ItemId id);
        bool removeVault(ItemId id);
        bool createVaultData();
        std::shared_ptr<Vault> createVault(Vendor vendor, ItemId id);

        /**
         * @brief Holds a map of registered vaults
         * @param ItemId Used to store the UUID of the main Vault
         * @param std::shared_ptr<Vault> Used to store a pointer to the Vault class to allow
         *  derived classes.
        */
        std::map<ItemId, std::shared_ptr<Vault>> m_pending_vaults_;
        std::map<ItemId, std::shared_ptr<Vault>> m_vaults_;
        ItemId m_main_vault_;
        Storage m_storage_;
        nlohmann::json m_data_;
    };
}