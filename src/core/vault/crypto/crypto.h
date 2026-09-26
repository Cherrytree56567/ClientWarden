#pragma once
#include <memory>
#include <botan/secmem.h>
#include "clientwarden.h"

namespace clientwarden::vault {
    /**
     * @brief Used to pass the type of checksum to generate from checksum().
    */
    enum class ChecksumType {
        Uri,
        SHA256
    };

    /**
     * @brief Used to hold the encryption and verification keys.
    */
    struct ItemKey {
        Botan::secure_vector<uint8_t> encKey;
        Botan::secure_vector<uint8_t> macKey;
    };

    /**
     * @brief Base Cryptography class for Vault.
     * 
     * Should be derived, as this is a base class.
    */
    class Crypto {
    public:
        Crypto();
        virtual ~Crypto() = default;

        /**
         * @brief Derive the Vault's InternalKey using the given password, salt and params.
         */
        virtual Botan::secure_vector<uint8_t> makeInternalKey(const Botan::secure_vector<uint8_t>& password, 
            const Botan::secure_vector<uint8_t>& salt, KDFParams params, 
            const Botan::secure_vector<uint8_t>& secret = Botan::secure_vector<uint8_t>{}) = 0;
        
        /**
         * @brief Verifies 2 Mac Keys against each other.
         */
        virtual bool macsEqual(const Botan::secure_vector<uint8_t>& mac_key, 
            const Botan::secure_vector<uint8_t>& mac1, const Botan::secure_vector<uint8_t>& mac2) = 0;

        /**
         * @brief Encrypts the Value using the provided Key.
         */
        virtual Botan::secure_vector<uint8_t> encrypt(const Botan::secure_vector<uint8_t>& value, 
            const ItemKey& key) = 0;
        /**
         * @brief Decrypts the Value using the provided Key.
         */
        virtual Botan::secure_vector<uint8_t> decrypt(const Botan::secure_vector<uint8_t>& value, 
            const ItemKey& key) = 0;

        /**
         * @brief Encrypts the Value using the provided Key as a Binary.
         */
        virtual Botan::secure_vector<uint8_t> encryptBinary(const Botan::secure_vector<uint8_t>& value, 
            const ItemKey& key) = 0;
        /**
         * @brief Decrypts the Value using the provided Key as a Binary.
         */
        virtual Botan::secure_vector<uint8_t> decryptBinary(const Botan::secure_vector<uint8_t>& value, 
            const ItemKey& key) = 0;

        /**
         * @brief Stretches a key using HKDF using the provided info param.
         */
        virtual Botan::secure_vector<uint8_t> hkdfStretch(const Botan::secure_vector<uint8_t>& info, 
            const Botan::secure_vector<uint8_t>& key) = 0;
        /**
         * @brief Hashes the value against the provided Internal Key.
         */
        virtual Botan::secure_vector<uint8_t> hashedPassword(const Botan::secure_vector<uint8_t>& value, 
            const Botan::secure_vector<uint8_t>& internal_key) = 0;

        /**
         * @brief Resolves an Protected Key using the Vault's own Auth Keys.
         */
        virtual ItemKey resolveItemKey(const Botan::secure_vector<uint8_t>& protected_key) = 0;
        /**
         * @brief Resolves an Protected Key using the provided Keys.
         */
        virtual ItemKey resolveItemKey(const Botan::secure_vector<uint8_t>& protected_key, 
            const ItemKey& key) = 0;

        /**
         * @brief Generate an Item Key
         */
        virtual ItemKey generateKey() = 0;

        /**
         * @brief Generates a checksum of the value using the provided Keys.
         */
        virtual Botan::secure_vector<uint8_t> checksum(const Botan::secure_vector<uint8_t>& value, 
            const ItemKey& key, ChecksumType type = ChecksumType::Uri) = 0;
        
        /**
         * @brief Sets m_auth_keys
         */
        virtual void setKeys(const AuthKeys& keys);
        /**
         * @brief Erases the Auth Keys from memory
         */
        virtual void eraseKeys();

        /**
         * @brief Returns the Vendor.
         */
        virtual Vendor getVendor() = 0;
    protected:
        /**
         * @brief setKeys will use the AuthKeys to generate the ItemKey
         */
        AuthKeys m_auth_keys;
        ItemKey m_keys;
    };
}