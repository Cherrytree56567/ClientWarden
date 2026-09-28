#include "bitwarden_crypto.h"

namespace clientwarden::vendor::bitwarden::vault {
    BitwardenCrypto::BitwardenCrypto() {

    }

    /**
     * @brief There are 2 ways to create an internal Key, PBKDF2 SHA256 or Argon2ID
     * 
     * For Argon2ID, Bitwarden requires you to hash the salt with SHA256 before using it.
     */
    std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> BitwardenCrypto::makeInternalKey(
        const Botan::secure_vector<uint8_t>& password, 
        const Botan::secure_vector<uint8_t>& salt, KDFParams params, 
        const Botan::secure_vector<uint8_t>& secret = Botan::secure_vector<uint8_t>{}) {
        Botan::secure_vector<uint8_t> internal_key(256 / 8);

        if (params.type == KDFType::PBKDF2_SHA256) {
            std::unique_ptr<Botan::PasswordHashFamily> family = 
                Botan::PasswordHashFamily::create("PBKDF2(SHA-256)");
            
            if (!family) {
                return std::unexpected(CryptoErrors::InvalidFamily);
            }

            std::unique_ptr<Botan::PasswordHash> pbkdf2 = 
                family->from_iterations(params.iterations);

            pbkdf2->derive_key(
                internal_key.data(), internal_key.size(),
                reinterpret_cast<const char*>(password.data()), password.size(),
                salt.data(), salt.size()
            );
        } else if (params.type == KDFType::Argon2ID) {
            std::unique_ptr<Botan::HashFunction> sha256 = Botan::HashFunction::create("SHA-256");
            
            if (!sha256) {
                return std::unexpected(CryptoErrors::InvalidFamily);
            }

            Botan::secure_vector<uint8_t> hashed_salt = sha256->process(salt);

            std::unique_ptr<Botan::PasswordHashFamily> family = 
                Botan::PasswordHashFamily::create("Argon2id");
            
            if (!family) {
                return std::unexpected(CryptoErrors::InvalidFamily);
            }

            std::unique_ptr<Botan::PasswordHash> argon = 
                family->from_params(memory * 1024, iterations, parallel);

            argon->derive_key(
                internal_key.data(), internal_key.size(),
                reinterpret_cast<const char*>(password.data()), password.size(),
                hashed_salt.data(), hashed_salt.size()
            );
        } else {
            std::unexpected(CryptoErrors::InvalidParams);
        }

        return internal_key;
    }
        
    std::expected<bool, CryptoErrors> BitwardenCrypto::macsEqual(const Botan::secure_vector<uint8_t>& mac_key, 
        const Botan::secure_vector<uint8_t>& mac1, const Botan::secure_vector<uint8_t>& mac2) {
        std::unique_ptr<Botan::MessageAuthenticationCode> hmac = 
            Botan::MessageAuthenticationCode::create("HMAC(SHA-256)");
        if (!hmac) {
            return std::unexpected(CryptoErrors::InvalidFamily);
        }

        hmac->set_key(mac_key.data(), mac_key.size());

        Botan::secure_vector<uint8_t> hmac_1 = hmac->process(mac1);
        Botan::secure_vector<uint8_t> hmac_2 = hmac->process(mac2);

        bool mac_check = hmac_1.size() == hmac_2.size() &&
            Botan::constant_time_compare(hmac_1.data(), hmac_2.data(), hmac1.size());

        Botan::secure_scrub_memory(hmac_1.data(), hmac_1.size());
        Botan::secure_scrub_memory(hmac_2.data(), hmac_2.size());

        return mac_check;
    }

    std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> BitwardenCrypto::encrypt(const Botan::secure_vector<uint8_t>& value, 
        const ItemKey& key) {
        Botan::AutoSeeded_RNG rng;
        Botan::secure_vector<uint8_t> init_vector = rng.random_vec(16);

        std::unique_ptr<Botan::Cipher_Mode> cipher =
            Botan::Cipher_Mode::create("AES-256/CBC/PKCS7", Botan::Cipher_Dir::Encryption);
        if (!cipher) {
            return std::unexpected(CryptoErrors::InvalidFamily);
        }
        cipher->set_key(key.enc_key.data(), key.enc_key.size());
        cipher->start(init_vector.data(), init_vector.size());

        Botan::secure_vector<uint8_t> enc_value(value.begin(), value.end());
        cipher->finish(enc_value);

        Botan::secure_vector<uint8_t> ivct;
        ivct.insert(ivct.end(), init_vector.begin(), init_vector.end());
        ivct.insert(ivct.end(), enc_value.begin(), enc_value.end());

        std::unique_ptr<Botan::MessageAuthenticationCode> hmac =
            Botan::MessageAuthenticationCode::create("HMAC(SHA-256)");
        if (!hmac) {
            return std::unexpected(CryptoErrors::InvalidFamily);
        }
        hmac->set_key(key.mac_key.data(), key.mac_key.size());
        Botan::secure_vector<uint8_t> mac = hmac->process(ivct);

        Botan::secure_vector<uint8_t> enc_str = cipherString(EncryptionType::AesCbc256_HmacSha256_B64, 
            utils::b64Encode(init_vector), utils::b64Encode(enc_value), utils::b64Encode(mac));

        Botan::secure_scrub_memory(init_vector.data(), init_vector.size());
        Botan::secure_scrub_memory(enc_value.data(), enc_value.size());
        Botan::secure_scrub_memory(ivct.data(), ivct.size());
        Botan::secure_scrub_memory(mac.data(), mac.size());
        return enc_str;
    }

    std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> BitwardenCrypto::decrypt(const Botan::secure_vector<uint8_t>& value, 
        const ItemKey& key) {
        
    }

    std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> BitwardenCrypto::encryptBinary(const Botan::secure_vector<uint8_t>& value, 
        const ItemKey& key) override;
    std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> BitwardenCrypto::decryptBinary(const Botan::secure_vector<uint8_t>& value, 
        const ItemKey& key) override;

    std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> BitwardenCrypto::hkdfStretch(const Botan::secure_vector<uint8_t>& info, 
        const Botan::secure_vector<uint8_t>& key) override;
    std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> BitwardenCrypto::hashedPassword(const Botan::secure_vector<uint8_t>& value, 
        const Botan::secure_vector<uint8_t>& internal_key) override;

    std::expected<ItemKey, CryptoErrors> BitwardenCrypto::resolveItemKey(const Botan::secure_vector<uint8_t>& protected_key) override;
    std::expected<ItemKey, CryptoErrors> BitwardenCrypto::resolveItemKey(const Botan::secure_vector<uint8_t>& protected_key, 
        const ItemKey& key) override;

    std::expected<ItemKey, CryptoErrors> BitwardenCrypto::generateKey() override;

    std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> BitwardenCrypto::checksum(const Botan::secure_vector<uint8_t>& value, 
        const ItemKey& key, ChecksumType type = ChecksumType::Uri) override;
        
    CryptoErrors BitwardenCrypto::setKeys(const AuthKeys& keys);
    CryptoErrors BitwardenCrypto::eraseKeys();

    Vendor BitwardenCrypto::getVendor() {
        return Vendor::BitWarden;
    }

    Botan::secure_vector<uint8_t> BitwardenCrypto::cipherString_(EncryptionType type, 
            const Botan::secure_vector<uint8_t>& init_vector, 
            const Botan::secure_vector<uint8_t>& value, 
            const Botan::secure_vector<uint8_t>& mac) {
        
    }
}