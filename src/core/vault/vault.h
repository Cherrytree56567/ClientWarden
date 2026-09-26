#pragma once
#include <memory>
#include <variant>
#include <botan/secmem.h>
#include "sync/sync.h"
#include "clientwarden.h"
#include "crypto/crypto.h"
#include "network/network.h"
#include "runtime/runtime.h"
#include "storage/storage.h"
#include "autofill/autofill.h"
#include "settings/settings.h"
#include "versioning/versioning.h"
#include "orchestrator/orchestrator.h"

namespace clientwarden {
    /**
     * @brief AuthResult is used to pass the auth status to the caller
     *
     * Note: Will return `Success` if the Vault is already authenticated.
    */
    enum class AuthResult {
        Failed,
        InvalidCreds,
        NetworkError,
        Success,
        Unknown
    };

    /**
     * @brief Holds the values to authenticate via password
     */
    struct PasswordCredential {
        Botan::secure_vector<uint8_t> m_email;
        Botan::secure_vector<uint8_t> m_password;
    };

    /**
     * @brief Holds the values to authenticate via totp/device verification
     */
    struct CodeCredential {
        Botan::secure_vector<uint8_t> m_code;
    };

    /**
     * @brief Holds the values to authenticate via passkey
     */
    struct PasskeyCredential {
        Botan::secure_vector<uint8_t> m_id;
        Botan::secure_vector<uint8_t> m_auth_data;
        Botan::secure_vector<uint8_t> m_client_data;
        Botan::secure_vector<uint8_t> m_signature;
    };

    /**
     * @brief Holds the values to unlock via password
    */
    struct UnlockPasswordCredential {
        Botan::secure_vector<uint8_t> m_password;
    };

    /**
     * @brief Holds the values to unlock via biometric
     * 
     * Intentionally empty since the biometric check is verified by the OS via keychain.
     */
    struct BiometricCredential {
        
    };

    /**
     * @brief Reperesents cred types that are accepted by login()
     */
    using Credential = std::variant<PasswordCredential, CodeCredential, PasskeyCredential>;

    /**
     * @brief Reperesents cred types that are accepted by signup()
     */
    using SignupCredential = std::variant<PasswordCredential>;

    /**
     * @brief Reperesents cred types that are accepted by unlock()
     */
    using UnlockCredential = std::variant<UnlockPasswordCredential, BiometricCredential>;

    /**
     * @brief Holds the current state the Vault is in
     */
    enum class AuthState {
        Unknown,
        LoggedOut,
        Unlockable,
        WaitingForTOTP,
        WaitingForDeviceVerif,
        WaitingForPasskey,
        Unlocked,
        Failed
    };

    /**
     * @brief Represents the Success or 2FA challenge that login can pass back
     */
    using LoginResult = std::variant<AuthResult, vault::MultiFactorChallenge>;

    class Vault {
    public:
        Vault(ItemId uuid);
        virtual ~Vault() = default;

        /**
         * @brief Authenticates with a Password, Code or Passkey creds and returns a 
         *  MultiFactorChallenge if additional 2FA is required
         */
        virtual LoginResult login(Credential cred) = 0;
        /**
         * @brief Creates a new account using the provided creds and returns an AuthResult
         */
        virtual AuthResult signup(SignupCredential cred) = 0;
        /**
         * @brief Unlocks the vault using a Password or Biometric auth
         */
        virtual AuthResult unlock(UnlockCredential cred) = 0;
        /**
         * @brief Clears sensitive data from memory and closes all active threads
         */
        virtual bool lock() = 0;
        /**
         * @brief Clears all sensitive data from memory, closes all active threads and deletes all
         *  keychain and vault folder.
         */
        virtual bool logout() = 0;

        /**
         * @brief Passes AuthKeys to Settings to setup Biometric Unlock
         */
        virtual bool setupBiometricUnlock(UnlockType type) = 0;

        /**
         * @brief Verifies Master Password for a reprompt check before revealing a
         *  sensitive item.
         */
        virtual bool checkReprompt(Botan::secure_vector<uint8_t> password) = 0;

        /**
         * @brief Retrieves an existing Item
         */
        template <typename Derived>
        std::shared_ptr<Derived> getDerivedItem(ItemId uuid) {
            return std::make_shared<Derived>(*this, uuid);
        }

        /**
         * @brief Creates an Item of the provided type
         */
        template <typename Derived>
        std::shared_ptr<Derived> createItem() {
            return std::make_shared<Derived>(*this);
        }
        
        /**
         * @brief Retrieves a generic item by UUID
         */
        virtual std::shared_ptr<GenericItem> getItem(ItemId uuid) = 0;
        /**
         * @brief Retrieves a folder with the provided uuid
         */
        virtual std::shared_ptr<Folder> getFolder(ItemId uuid) = 0;
        /**
         * @brief Creates a folder
         */
        virtual std::shared_ptr<Folder> createFolder() = 0;
        /**
         * @brief Retrieves a Cipher Query
         */
        virtual std::shared_ptr<CipherQuery> getCipherQuery() = 0;

        /**
         * @brief Retrieves the Current Auth State of the Vault
         */
        AuthState getState();
        /**
         * @brief Returns the Vault's Orchestrator
         */
        std::shared_ptr<vault::Orchestrator> getOrchestrator();
        /**
         * @brief Returns the Vault's Versioning System
         */
        std::shared_ptr<vault::Versioning> getVersioning();
        /**
         * @brief Returns the Vault's Settings
         */
        std::shared_ptr<vault::Settings> getSettings();
        /**
         * @brief Returns the Vault's AutoFill
         */
        std::shared_ptr<vault::AutoFill> getAutoFill();

        /**
         * @brief Returns the Vendor of the Vault
         */
        virtual Vendor getVendor() = 0;
    protected:
        /**
         * @brief Returns the Vault's Private Storage
         */
        std::shared_ptr<Storage> getStorage();

        AuthState m_state;
        std::shared_ptr<vault::Crypto> m_crypto;
        std::shared_ptr<vault::Network> m_network;
        std::shared_ptr<vault::Settings> m_settings;
        std::shared_ptr<vault::Versioning> m_versioning;
        std::shared_ptr<vault::Runtime> m_runtime;
        std::shared_ptr<vault::Orchestrator> m_orchestrator;
        std::shared_ptr<vault::Sync> m_sync;
        std::shared_ptr<vault::AutoFill> m_autofill;

    private:
        /**
         * @brief Each Vault has its own storage path which is passed by the VaultManager.
        */
        std::shared_ptr<Storage> m_storage_;
        ItemId m_uuid_;
    };
}