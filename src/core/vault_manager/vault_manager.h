#pragma once
#include <memory>
#include <botan/secmem.h>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include "vault/vault.h"

namespace clientwarden {
    /*
     * @brief Holds and manages multiple vaults
    */
    class VaultManager {
    public:
        VaultManager();
        ~VaultManager();

        VaultManager& instance();

        boost::uuids::uuid getMainVault();
        std::shared_ptr<Vault> getVault(boost::uuids::uuid uuid);
        Botan::secure_vector<boost::uuids::uuid> getVaultUUIDs();

        size_t getVaultCount();
        bool vaultExists(boost::uuids::uuid uuid);

        std::optional<boost::uuids::uuid> login(Credential cred, AuthResult& o_result);
        std::optional<boost::uuids::uuid> signup(Credential cred, AuthResult& o_result);
        bool logout(boost::uuids::uuid uuid);
        bool lock(boost::uuids::uuid uuid);

        bool logoutAll();
        bool lockAll();
    
    private:
        bool loadVaults();
        /*
         * @brief Holds a map of registered vaults
         * @param boost::uuids::uuid Used to store the UUID of the Vault
         * @param std::shared_ptr<Vault> Used to store a pointer to the Vault class to allow
         *  derived classes.
        */
        std::map<boost::uuids::uuid, std::shared_ptr<Vault>> m_vaults_;
        boost::uuids::uuid m_main_vault_;
    };
}