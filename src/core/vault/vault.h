#pragma once
#include <memory>
#include <botan/secmem.h>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>

/*
 * TODO: Create Storage
*/
namespace clientwarden {
    /*
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

    struct PasswordCredential {
        Botan::secure_vector<uint8_t> m_email;
        Botan::secure_vector<uint8_t> m_password;
    };

    struct CodeCredential {
        Botan::secure_vector<uint8_t> m_code;
    };

    struct PasskeyCredential {
        Botan::secure_vector<uint8_t> m_id;
        Botan::secure_vector<uint8_t> m_auth_data;
        Botan::secure_vector<uint8_t> m_client_data;
        Botan::secure_vector<uint8_t> m_signature;
    };

    struct UnlockPasswordCredential {
        Botan::secure_vector<uint8_t> m_password;
    };

    struct BiometricCredential {
        /*
         * Intentionally empty
        */
    }

    using Credential = std::variant<PasswordCredential, CodeCredential, PasskeyCredential>;
    using SignupCredential = std::variant<PasswordCredential>;
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
        Vault();

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
        std::shared_ptr<Derived> GetItem(std::string uuid) {
            return std::make_shared<Derived>(*this, uuid);
        }

        template <typename Derived>
        std::shared_ptr<Derived> CreateItem() {
            return std::make_shared<Derived>(*this);
        }
        
        std::shared_ptr<GenericItem> GetItem(std::string uuid);
        std::shared_ptr<Folder> GetFolder(std::string uuid);
        std::shared_ptr<Folder> CreateFolder();
        std::vector<std::string> GetFolders();
        std::shared_ptr<CipherQuery> GetCipherQuery();

        bool setStorage(std::shared_ptr<Storage> storage);

        AuthState getState();
    protected:
        AuthState m_state;
        /*
         * TODO: Store Vault Stuff here like Crypto, Network, etc
        */
    private:
        /*
         * @brief Each Vault has its own storage path which is passed by the VaultManager.
        */
        std::shared_ptr<Storage> m_storage_;
    };
}