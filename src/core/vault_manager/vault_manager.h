#pragma once
#include <map>
#include <memory>
#include <optional>
#include <botan/secmem.h>
#include "vault/vault.h"

namespace clientwarden {
    /**
     * @brief Stores all the possible errors for the VaultManager
     */
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

        /**
         * @brief Returns a static instance of the VaultManager
         */
        VaultManager& instance();

        /**
         * @brief Returns an ID of the main Vault
         */
        ItemId getMainVault();
        /**
         * @brief Returns the vault with the matching id
         */
        std::expected<std::shared_ptr<Vault>, VaultManagerError> getVault(ItemId uuid);
        /**
         * @brief Returns a list of all the Vault UUIDs
         */
        Botan::secure_vector<ItemId> getVaultUUIDs();

        /**
         * @brief Gets the total amount of vaults in m_vault_
         */
        size_t getVaultCount();
        /**
         * @brief Checks if a Vault with the provided uuid exists
         */
        bool vaultExists(ItemId uuid);

        /**
         * @brief Creates a Vault for the provided Vendor and runs login() on the generated Vault
         *  and if successful returns the LoginResult and sets the ItemId
         */
        std::expected<LoginResult, VaultManagerError> login(Credential cred, Vendor vendor, ItemId& o_id);
        /**
         * @brief Searches for an existing Vault with the provided ItemId and runs login() with the 
         *  provided creds, and if successful, moves the vault to m_vaults_ and returns the LoginResult.
         */
        std::expected<LoginResult, VaultManagerError> continueLogin(Credential cred, ItemId id);
        /**
         * @brief Creates a Vault for the provided Vendor and runs signup() on the generated Vault
         *  and if successful returns the AuthResult and sets the ItemId.
         */
        std::expected<AuthResult, VaultManagerError> signup(SignupCredential cred, Vendor vendor, ItemId& o_id);

        /**
         * @brief Runs logout() on the vault, removes it from the vault map and the local db.
         */
        bool logout(ItemId uuid);
        /**
         * @brief Runs lock() on the Vault with the provided id
         */
        bool lock(ItemId uuid);

        /**
         * @brief Runs logout() on all Vaults in m_vaults_
         */
        bool logoutAll();
        /**
         * @brief Runs lock() on all the Vaults in m_vaults_
         */
        bool lockAll();
    
    private:
        /**
         * @brief Loads all registered vaults from the JSON and loads them into m_vaults_
         */
        bool loadVaults();
        /**
         * @brief Provides the Vendor from std::string
         */
        Vendor getVendor(std::string vendor);
        /**
         * @brief Provides the std::string from the Vendor
         */
        std::string getVendorString(Vendor vendor);
        /**
         * @brief Saves the Vault with the provided id in the vaults JSON
         */
        bool saveVault(Vendor vendor, ItemId id);
        /**
         * @brief Removes the Vault with the provided id from the vaults JSON
         */
        bool removeVault(ItemId id);
        /**
         * @brief Pregenerates the default Vaults JSON Data
         */
        bool createVaultData();
        /**
         * @brief Creates a Vault from the appropriate Vendor and ItemId
         */
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