#pragma once
#include <memory>
#include <botan/secmem.h>
#include "clientwarden.h"

namespace clientwarden::vault {
    /**
     * @brief Used to pass the type of checksum to generate from checksum()
    */
    enum class ChecksumType {
        Uri,
        SHA256
    };

    /**
     * @brief Used to hold the encryption and verification keys
    */
    struct ItemKey {
        Botan::secure_vector<uint8_t> encKey;
        Botan::secure_vector<uint8_t> macKey;
    };

    /**
     * @brief Base Cryptography class for Vault
     * 
     * Should be derived, as this is a base class.
    */
    class Crypto {
    public:
        Crypto();
        virtual ~Crypto() = default;

        virtual Botan::secure_vector<uint8_t> makeInternalKey(const Botan::secure_vector<uint8_t>& password, 
            const Botan::secure_vector<uint8_t>& salt, KDFParams params, 
            const Botan::secure_vector<uint8_t>& secret = Botan::secure_vector<uint8_t>{}) = 0;
        
        virtual bool macsEqual(const Botan::secure_vector<uint8_t>& mac_key, 
            const Botan::secure_vector<uint8_t>& mac1, const Botan::secure_vector<uint8_t>& mac2) = 0;

        virtual Botan::secure_vector<uint8_t> encrypt(const Botan::secure_vector<uint8_t>& value, 
            const ItemKey& key) = 0;
        virtual Botan::secure_vector<uint8_t> decrypt(const Botan::secure_vector<uint8_t>& value, 
            const ItemKey& key) = 0;

        virtual Botan::secure_vector<uint8_t> encryptBinary(const Botan::secure_vector<uint8_t>& value, 
            const ItemKey& key) = 0;
        virtual Botan::secure_vector<uint8_t> decryptBinary(const Botan::secure_vector<uint8_t>& value, 
            const ItemKey& key) = 0;

        virtual Botan::secure_vector<uint8_t> hkdfStretch(const Botan::secure_vector<uint8_t>& info, 
            const Botan::secure_vector<uint8_t>& key) = 0;
        virtual Botan::secure_vector<uint8_t> hashedPassword(const Botan::secure_vector<uint8_t>& value, 
            const Botan::secure_vector<uint8_t>& internal_key) = 0;

        virtual ItemKey resolveItemKey(const Botan::secure_vector<uint8_t>& protected_key) = 0;
        virtual ItemKey resolveItemKey(const Botan::secure_vector<uint8_t>& protected_key, 
            const ItemKey& key) = 0;

        virtual ItemKey generateKey() = 0;

        virtual Botan::secure_vector<uint8_t> checksum(const Botan::secure_vector<uint8_t>& value, 
            const ItemKey& key, ChecksumType type = ChecksumType::Uri) = 0;
        
        virtual void setKeys(const AuthKeys& keys);
        virtual void eraseKeys();

        virtual Vendor getVendor() = 0;
    protected:
        /**
         * @brief setKeys will use the AuthKeys to generate the ItemKey
         */
        AuthKeys m_auth_keys;
        ItemKey m_keys;
    };
}