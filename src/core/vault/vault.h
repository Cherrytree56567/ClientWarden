#pragma once
#include <memory>
#include <variant>
#include <botan/secmem.h>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include "crypto/crypto.h"
#include "network/network.h"
#include "network/versioning.h"

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

    class Vault {
    public:
        Vault(boost::uuids::uuid uuid);

        AuthResult login(Credential cred);
        AuthResult signup(SignupCredential cred);
        AuthResult unlock(UnlockCredential cred);
        bool lock();
        bool logout();

        bool isBiometricUnlockActive();
        bool setupBiometricUnlock();
        bool removeBiometricUnlock();

        bool checkReprompt(Botan::secure_vector<uint8_t> password);

        template <typename Derived>
        std::shared_ptr<Derived> getItem(boost::uuids::uuid uuid) {
            return std::make_shared<Derived>(*this, uuid);
        }

        template <typename Derived>
        std::shared_ptr<Derived> createItem() {
            return std::make_shared<Derived>(*this);
        }
        
        std::shared_ptr<GenericItem> getItem(boost::uuids::uuid uuid);
        std::shared_ptr<Folder> getFolder(boost::uuids::uuid uuid);
        std::shared_ptr<Folder> createFolder();
        std::shared_ptr<CipherQuery> getCipherQuery();

        AuthState getState();
    protected:
        std::shared_ptr<Storage> getStorage();

        AuthState m_state;
        /*
         * TODO: Store Vault Stuff here like Crypto, Network, etc
        */
        std::shared_ptr<vault::Crypto> m_crypto;
        std::shared_ptr<vault::Network> m_network;
        std::shared_ptr<vault::Settings> m_settings;
        std::shared_ptr<vault::Versioning> m_versioning;
        std::shared_ptr<vault::Runtime> m_runtime;

    private:
        /**
         * @brief Each Vault has its own storage path which is passed by the VaultManager.
        */
        std::shared_ptr<Storage> m_storage_;
        boost::uuids::uuid m_uuid;
    };
}