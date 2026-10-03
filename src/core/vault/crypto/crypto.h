#pragma once
#include <memory>
#include <expected>
#include <ranges>
#include <utility>
#include <botan/secmem.h>
#include <botan/pwdhash.h>
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
     * @brief Holds Crypto Errors.
     */
    enum class CryptoErrors {
        InvalidParams,
        InvalidFamily,
        DecryptionError,
        Unsupported,
        None,
        Success
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
        virtual std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> makeInternalKey(
            const Botan::secure_vector<uint8_t>& password, 
            const Botan::secure_vector<uint8_t>& salt, KDFParams params, 
            const Botan::secure_vector<uint8_t>& secret = Botan::secure_vector<uint8_t>{}) = 0;
        
        /**
         * @brief Verifies 2 Mac Keys against each other.
         */
        virtual std::expected<bool, CryptoErrors> macsEqual(
            const Botan::secure_vector<uint8_t>& mac_key, const Botan::secure_vector<uint8_t>& mac1,
            const Botan::secure_vector<uint8_t>& mac2) = 0;

        /**
         * @brief Encrypts the Value using the provided Key.
         */
        virtual std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> encrypt(
            const Botan::secure_vector<uint8_t>& value, const ItemKey& key) = 0;
        /**
         * @brief Decrypts the Value using the provided Key.
         */
        virtual std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> decrypt(
            const Botan::secure_vector<uint8_t>& value, const ItemKey& key) = 0;

        /**
         * @brief Encrypts the Value using the provided Key as a Binary.
         */
        virtual std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> encryptBinary(
            const Botan::secure_vector<uint8_t>& value, const ItemKey& key) = 0;
        /**
         * @brief Decrypts the Value using the provided Key as a Binary.
         */
        virtual std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> decryptBinary(
            const Botan::secure_vector<uint8_t>& value, const ItemKey& key) = 0;

        /**
         * @brief Stretches a key using HKDF using the provided info param.
         */
        virtual std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> hkdfStretch(
            const Botan::secure_vector<uint8_t>& info) = 0;
        /**
         * @brief Hashes the value against the provided Internal Key.
         */
        virtual std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> hashedPassword(
            const Botan::secure_vector<uint8_t>& value, 
            const Botan::secure_vector<uint8_t>& internal_key) = 0;

        /**
         * @brief Resolves an Protected Key using the Vault's own Auth Keys.
         */
        virtual std::expected<ItemKey, CryptoErrors> resolveItemKey(
            const Botan::secure_vector<uint8_t>& protected_key) = 0;
        /**
         * @brief Resolves an Protected Key using the provided Keys.
         */
        virtual std::expected<ItemKey, CryptoErrors> resolveItemKey(
            const Botan::secure_vector<uint8_t>& protected_key, const ItemKey& key) = 0;

        /**
         * @brief Generate an Item Key.
         */
        virtual std::expected<ItemKey, CryptoErrors> generateKey() = 0;

        /**
         * @brief Generates a checksum of the value using the provided Keys.
         */
        virtual std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> checksum(
            const Botan::secure_vector<uint8_t>& value, const ItemKey& key, 
            ChecksumType type = ChecksumType::Uri) = 0;
        
        /**
         * @brief Sets m_auth_keys.
         */
        virtual CryptoErrors setAuthKeys(const AuthKeys& keys) = 0;
        /**
         * @brief Generates the ItemKey and sets m_keys.
         */
        virtual CryptoErrors setVaultKeys(Botan::secure_vector<uint8_t> protected_key) = 0;
        /**
         * @brief Erases the Auth Keys from memory.
         */
        virtual CryptoErrors eraseKeys() = 0;

        /**
         * @brief Returns the Vendor.
         */
        virtual Vendor getVendor() = 0;
    protected:
        AuthKeys m_auth_keys;
        ItemKey m_keys;
    };
}