#pragma once
#include "vault/crypto/crypto.h"

namespace clientwarden::vendor::bitwarden::vault {
    /**
     * @brief Holds all the BitWarden Encryption Types.
     * Found from BitWarden Clients Repo:
     * https://github.com/bitwarden/clients/blob/main/libs/legacy-crypto/src/enums/encryption-type.enum.ts
     */
    enum EncryptionType : uint8_t {
        AesCbc256_B64 = 0,
        AesCbc128_HmacSha256_B64 = 1,
        AesCbc256_HmacSha256_B64 = 2,
        Rsa2048_OaepSha256_B64 = 3,
        Rsa2048_OaepSha1_B64 = 4,
        Rsa2048_OaepSha256_HmacSha256_B64 = 5,
        Rsa2048_OaepSha1_HmacSha256_B64 = 6,
        CoseEncrypt0 = 7,
    };

    class BitwardenCrypto : public Crypto {
    public:
        BitwardenCrypto();
        ~BitwardenCrypto() override = default;

        /**
         * @brief See `crypto.h` - Crypto for all briefs
         */
        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> makeInternalKey(
            const Botan::secure_vector<uint8_t>& password, 
            const Botan::secure_vector<uint8_t>& salt, KDFParams params, 
            const Botan::secure_vector<uint8_t>& secret = Botan::secure_vector<uint8_t>{}) override;
        
        std::expected<bool, CryptoErrors> macsEqual(
            const Botan::secure_vector<uint8_t>& mac_key, const Botan::secure_vector<uint8_t>& mac1, 
            const Botan::secure_vector<uint8_t>& mac2) override;

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> encrypt(
            const Botan::secure_vector<uint8_t>& value, const ItemKey& key) override;
        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> decrypt(
            const Botan::secure_vector<uint8_t>& value, const ItemKey& key) override;

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> encryptBinary(
            const Botan::secure_vector<uint8_t>& value, const ItemKey& key) override;
        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> decryptBinary(
            const Botan::secure_vector<uint8_t>& value, const ItemKey& key) override;

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> hkdfStretch(
            const Botan::secure_vector<uint8_t>& info) override;
        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> hashedPassword(
            const Botan::secure_vector<uint8_t>& value, 
            const Botan::secure_vector<uint8_t>& internal_key) override;

        std::expected<ItemKey, CryptoErrors> resolveItemKey(
            const Botan::secure_vector<uint8_t>& protected_key) override;
        std::expected<ItemKey, CryptoErrors> resolveItemKey(
            const Botan::secure_vector<uint8_t>& protected_key, const ItemKey& key) override;

        std::expected<ItemKey, CryptoErrors> generateKey() override;

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> checksum(
            const Botan::secure_vector<uint8_t>& value, const ItemKey& key, 
            ChecksumType type = ChecksumType::Uri) override;
        
        CryptoErrors setKeys(const AuthKeys& keys) override;
        CryptoErrors setVaultKeys(Botan::secure_vector<uint8_t> protected_key) override;
        CryptoErrors eraseKeys() override;

        Vendor getVendor() override;
    private:
        Botan::secure_vector<uint8_t> cipherString_(EncryptionType type, 
            const Botan::secure_vector<uint8_t>& init_vector, 
            const Botan::secure_vector<uint8_t>& value, 
            const Botan::secure_vector<uint8_t>& mac);
        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> decryptAesCbc256_HmacSha256_B64(
            const Botan::secure_vector<uint8_t>& init_vector, 
            const Botan::secure_vector<uint8_t>& enc_value, 
            const Botan::secure_vector<uint8_t>& mac, const ItemKey& key);
        std::expected<void, CryptoErrors> encryptAesCbc256_HmacSha256_B64(
            const Botan::secure_vector<uint8_t>& value, const ItemKey& key,
            Botan::secure_vector<uint8_t>& init_vector, Botan::secure_vector<uint8_t>& enc_value, 
            Botan::secure_vector<uint8_t>& mac);
    };
}