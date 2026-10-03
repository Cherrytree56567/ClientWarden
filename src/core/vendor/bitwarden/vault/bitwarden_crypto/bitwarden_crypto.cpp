#include "bitwarden_crypto.h"

namespace clientwarden::vendor::bitwarden::vault {
    BitwardenCrypto::BitwardenCrypto() {

    }

    /**
     * @brief There are 2 ways to create an internal Key, PBKDF2 SHA256 or Argon2ID
     * 
     * For Argon2ID, Bitwarden requires you to hash the salt with SHA256 before using it.
     * Here, secret is unused as that is a 1Pass feature (Secret Key)
     */
    std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> BitwardenCrypto::makeInternalKey(
        const Botan::secure_vector<uint8_t>& password, 
        const Botan::secure_vector<uint8_t>& salt, KDFParams params, 
        const Botan::secure_vector<uint8_t>& secret) {
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
                family->from_params(params.memory * 1024, params.iterations, params.parallel);

            argon->derive_key(
                internal_key.data(), internal_key.size(),
                reinterpret_cast<const char*>(password.data()), password.size(),
                hashed_salt.data(), hashed_salt.size()
            );
        } else {
            return std::unexpected(CryptoErrors::InvalidParams);
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
            Botan::constant_time_compare(hmac_1.data(), hmac_2.data(), hmac_1.size());

        Botan::secure_scrub_memory(hmac_1.data(), hmac_1.size());
        Botan::secure_scrub_memory(hmac_2.data(), hmac_2.size());

        return mac_check;
    }

    std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> BitwardenCrypto::encrypt(const Botan::secure_vector<uint8_t>& value, 
        const ItemKey& key) {
        EncryptionType enc_type = EncryptionType::AesCbc256_HmacSha256_B64;

        Botan::secure_vector<uint8_t> init_vector;
        Botan::secure_vector<uint8_t> enc_value;
        Botan::secure_vector<uint8_t> mac;

        switch (enc_type) {
            case EncryptionType::AesCbc256_HmacSha256_B64: {
                std::expected<void, CryptoErrors> result = 
                    encryptAesCbc256_HmacSha256_B64(value, key, init_vector, enc_value, mac);
                
                if (!result) {
                    return std::unexpected(result.error());
                }
                break;
            }
                
            default:
                return std::unexpected(CryptoErrors::Unsupported);
        }

        Botan::secure_vector<uint8_t> enc_str = cipherString_(enc_type, utils::b64Encode(init_vector), 
            utils::b64Encode(enc_value), utils::b64Encode(mac));

        Botan::secure_scrub_memory(init_vector.data(), init_vector.size());
        Botan::secure_scrub_memory(enc_value.data(), enc_value.size());
        Botan::secure_scrub_memory(mac.data(), mac.size());
        return enc_str;
    }

    std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> BitwardenCrypto::decrypt(const Botan::secure_vector<uint8_t>& value, 
        const ItemKey& key) {
        try {
            if (value.size() < 2 || value[1] != '.') {
                return std::unexpected(CryptoErrors::InvalidParams);
            }

            char c_enc_type = static_cast<char>(value[0]);

            if (c_enc_type < '0' || c_enc_type > '9') {
                return std::unexpected(CryptoErrors::InvalidParams);
            }

            EncryptionType enc_type = static_cast<EncryptionType>(c_enc_type - '0');

            std::vector<Botan::secure_vector<uint8_t>> parts;
            Botan::secure_vector<uint8_t> actual_value(value.begin() + 2, value.end());

            for (std::ranges::subrange<Botan::secure_vector<uint8_t>::iterator> part : actual_value | std::views::split(uint8_t{'|'})) {
                parts.emplace_back(part.begin(), part.end());
            }
            
            Botan::secure_scrub_memory(actual_value.data(), actual_value.size());

            if (parts.size() != 3) {
                parts.clear();
                return std::unexpected(CryptoErrors::InvalidParams);
            }

            Botan::secure_vector<uint8_t> init_vector = utils::b64Decode(parts[0]);
            Botan::secure_vector<uint8_t> enc_value = utils::b64Decode(parts[1]);
            Botan::secure_vector<uint8_t> mac = utils::b64Decode(parts[2]);

            parts.clear();

            switch (enc_type) {
                case EncryptionType::AesCbc256_HmacSha256_B64:
                    return decryptAesCbc256_HmacSha256_B64(init_vector, enc_value, mac, key);
                
                default:
                    return std::unexpected(CryptoErrors::Unsupported);
            }

            return std::unexpected(CryptoErrors::Unsupported);
        } catch(...) {
            return std::unexpected(CryptoErrors::DecryptionError);
        }
    }

    std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> BitwardenCrypto::encryptBinary(
        const Botan::secure_vector<uint8_t>& value, const ItemKey& key) {
        EncryptionType enc_type = EncryptionType::AesCbc256_HmacSha256_B64;

        Botan::secure_vector<uint8_t> init_vector;
        Botan::secure_vector<uint8_t> enc_value;
        Botan::secure_vector<uint8_t> mac;

        switch (enc_type) {
            case EncryptionType::AesCbc256_HmacSha256_B64: {
                std::expected<void, CryptoErrors> result = 
                    encryptAesCbc256_HmacSha256_B64(value, key, init_vector, enc_value, mac);
                
                if (!result) {
                    return std::unexpected(result.error());
                }
                break;
            }
                
            default:
                return std::unexpected(CryptoErrors::Unsupported);
        }

        Botan::secure_vector<uint8_t> result;
        result.reserve(1 + init_vector.size() + mac.size() + enc_value.size());
        result.push_back(std::to_underlying(enc_type));
        result.insert(result.end(), init_vector.begin(), init_vector.end());
        result.insert(result.end(), mac.begin(), mac.end());
        result.insert(result.end(), enc_value.begin(), enc_value.end());

        return result;
    }
    
    std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> BitwardenCrypto::decryptBinary(const Botan::secure_vector<uint8_t>& value, 
        const ItemKey& key) {
        try {
            if (value.size() < 65 || (value.size() - 49) % 16 != 0) {
                return std::unexpected(CryptoErrors::InvalidParams);
            }

            uint8_t raw_type = value[0];

            if (raw_type > 9) {
                return std::unexpected(CryptoErrors::InvalidParams);
            }

            EncryptionType enc_type = static_cast<EncryptionType>(raw_type);

            Botan::secure_vector<uint8_t> init_vector(value.begin() + 1, value.begin() + 17);
            Botan::secure_vector<uint8_t> enc_value(value.begin() + 49, value.end());
            Botan::secure_vector<uint8_t> mac(value.begin() + 17, value.begin() + 49);

            switch (enc_type) {
                case EncryptionType::AesCbc256_HmacSha256_B64:
                    return decryptAesCbc256_HmacSha256_B64(init_vector, enc_value, mac, key);
                
                default:
                    return std::unexpected(CryptoErrors::Unsupported);
            }

            return std::unexpected(CryptoErrors::Unsupported);
        } catch(...) {
            return std::unexpected(CryptoErrors::DecryptionError);
        }
    }

    std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> BitwardenCrypto::hkdfStretch(const Botan::secure_vector<uint8_t>& info) {
        Botan::secure_vector<uint8_t> data(info.begin(), info.end());
        data.push_back(0x01);

        std::unique_ptr<Botan::MessageAuthenticationCode> hmac =
            Botan::MessageAuthenticationCode::create("HMAC(SHA-256)");
        if (!hmac) {
            return std::unexpected(CryptoErrors::InvalidFamily);
        }

        hmac->set_key(m_auth_keys.internal_key);
        hmac->update(data);
        Botan::secure_vector<uint8_t> result = hmac->final();

        return result;
    }

    std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> BitwardenCrypto::hashedPassword(const Botan::secure_vector<uint8_t>& value, 
        const Botan::secure_vector<uint8_t>& internal_key) {
        Botan::secure_vector<uint8_t> hashed(32);

        std::unique_ptr<Botan::PasswordHashFamily> family =
            Botan::PasswordHashFamily::create("PBKDF2(SHA-256)");
        if (!family) {
            return std::unexpected(CryptoErrors::InvalidFamily);
        }

        std::unique_ptr<Botan::PasswordHash> pbkdf2 = family->from_params(1);

        pbkdf2->derive_key(hashed.data(), hashed.size(), 
            reinterpret_cast<const char*>(internal_key.data()), internal_key.size(),
            value.data(), value.size());

        Botan::secure_vector<uint8_t> result = utils::b64Encode(hashed);

        Botan::secure_scrub_memory(hashed.data(), hashed.size());
        
        return result;
    }

    std::expected<ItemKey, CryptoErrors> BitwardenCrypto::resolveItemKey(const Botan::secure_vector<uint8_t>& protected_key) {
        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> item_key = decrypt(protected_key, m_keys);

        if (!item_key) {
            return std::unexpected(item_key.error());
        }

        ItemKey key;

        if (item_key.value().size() != 64) {
            return std::unexpected(CryptoErrors::InvalidParams);
        }

        key.enc_key = Botan::secure_vector<uint8_t>(item_key.value().begin(), item_key.value().begin() + 32);
        key.mac_key = Botan::secure_vector<uint8_t>(item_key.value().begin() + 32, item_key.value().end());

        Botan::secure_scrub_memory(item_key.value().data(), item_key.value().size());

        return key;
    }

    std::expected<ItemKey, CryptoErrors> BitwardenCrypto::resolveItemKey(const Botan::secure_vector<uint8_t>& protected_key, 
        const ItemKey& key) {
        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> item_key = decrypt(protected_key, key);

        if (!item_key) {
            return std::unexpected(item_key.error());
        }

        ItemKey result;

        if (item_key.value().size() != 64) {
            return std::unexpected(CryptoErrors::InvalidParams);
        }

        result.enc_key = Botan::secure_vector<uint8_t>(item_key.value().begin(), item_key.value().begin() + 32);
        result.mac_key = Botan::secure_vector<uint8_t>(item_key.value().begin() + 32, item_key.value().end());

        Botan::secure_scrub_memory(item_key.value().data(), item_key.value().size());

        return result;
    }

    std::expected<ItemKey, CryptoErrors> BitwardenCrypto::generateKey() {
        Botan::AutoSeeded_RNG rng;

        ItemKey key;
        key.enc_key = rng.random_vec(32);
        key.mac_key = rng.random_vec(32);

        return key;
    }

    std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> BitwardenCrypto::checksum(const Botan::secure_vector<uint8_t>& value, 
        const ItemKey& key, ChecksumType type) {
        std::unique_ptr<Botan::HashFunction> sha256 = Botan::HashFunction::create("SHA-256");
        if (!sha256) {
            return std::unexpected(CryptoErrors::InvalidFamily);
        }

        Botan::secure_vector<uint8_t> result = sha256->process(value),
            value.size());
        
        if (type == ChecksumType::Uri) {
            return encrypt(utils::b64Encode(result), key);
        }

        return result;
    }
        
    CryptoErrors BitwardenCrypto::setKeys(const AuthKeys& keys) {
        m_auth_keys = keys;

        return CryptoErrors::Success;
    }

    CryptoErrors BitwardenCrypto::setVaultKeys(Botan::secure_vector<uint8_t> protected_key) {
        ItemKey stretched_key;

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> enc_res = 
            hkdfStretch(Botan::secure_vector<uint8_t>({'e', 'n', 'c'}));
        if (!enc_res.has_value()) {
            return enc_res.error();
        }

        std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> mac_res = 
            hkdfStretch(Botan::secure_vector<uint8_t>({'m', 'a', 'c'}));
        if (!mac_res.has_value()) {
            return mac_res.error();
        }
        
        stretched_key.enc_key = enc_res.value();
        stretched_key.mac_key = mac_res.value();

        std::expected<ItemKey, CryptoErrors> result = resolveItemKey(protected_key, stretched_key);

        if (!result.has_value()) {
            return result.error();
        }

        m_keys = result.value();

        return CryptoErrors::Success;
    }

    CryptoErrors BitwardenCrypto::eraseKeys() {
        m_auth_keys.clear();
        m_keys.clear();
        return CryptoErrors::Success;
    }

    Vendor BitwardenCrypto::getVendor() {
        return Vendor::BitWarden;
    }

    Botan::secure_vector<uint8_t> BitwardenCrypto::cipherString_(EncryptionType type, 
        const Botan::secure_vector<uint8_t>& init_vector, 
        const Botan::secure_vector<uint8_t>& value, 
        const Botan::secure_vector<uint8_t>& mac) {
        Botan::secure_vector<uint8_t> result;
        result.reserve(2 + init_vector.size() + 1 + value.size() + (!mac.empty() ? (1 + mac.size()) : 0));

        result.push_back(static_cast<uint8_t>('0' + std::to_underlying(type)));
        result.push_back('.');
        result.insert(result.end(), init_vector.begin(), init_vector.end());
        result.push_back('|');
        result.insert(result.end(), value.begin(), value.end());

        if (!mac.empty()) {
            result.push_back('|');
            result.insert(result.end(), mac.begin(), mac.end());
        }

        return result;
    }

    std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> BitwardenCrypto::decryptAesCbc256_HmacSha256_B64(
        const Botan::secure_vector<uint8_t>& init_vector, 
        const Botan::secure_vector<uint8_t>& enc_value, 
        const Botan::secure_vector<uint8_t>& mac, const ItemKey& key) {
        if (init_vector.size() != 16 || enc_value.empty() || 
            enc_value.size() % 16 != 0 || mac.size() != 32) {
            return std::unexpected(CryptoErrors::InvalidParams);
        }

        Botan::secure_vector<uint8_t> ivct;
        ivct.insert(ivct.end(), init_vector.begin(), init_vector.end());
        ivct.insert(ivct.end(), enc_value.begin(), enc_value.end());

        std::unique_ptr<Botan::MessageAuthenticationCode> hmac =
            Botan::MessageAuthenticationCode::create("HMAC(SHA-256)");
        
        if (!hmac) {
            Botan::secure_scrub_memory(ivct.data(), ivct.size());
            return std::unexpected(CryptoErrors::InvalidFamily);
        }

        if (!hmac->valid_keylength(key.mac_key.size())) {
            Botan::secure_scrub_memory(ivct.data(), ivct.size());
            return std::unexpected(CryptoErrors::InvalidParams);
        }

        hmac->set_key(key.mac_key);
        hmac->update(ivct);

        bool mac_check = hmac->verify_mac(mac.data(), mac.size());

        Botan::secure_scrub_memory(ivct.data(), ivct.size());

        if (!mac_check) {
            return std::unexpected(CryptoErrors::DecryptionError);
        }

        std::unique_ptr<Botan::Cipher_Mode> cipher_mode = 
            Botan::Cipher_Mode::create("AES-256/CBC/PKCS7", Botan::Cipher_Dir::Decryption);

        if (!cipher_mode) {
            return std::unexpected(CryptoErrors::InvalidFamily);
        }

        if (!cipher_mode->valid_keylength(key.enc_key.size())) {
            return std::unexpected(CryptoErrors::InvalidParams);
        }

        if (!cipher_mode->valid_nonce_length(init_vector.size())) {
            return std::unexpected(CryptoErrors::InvalidParams);
        }

        cipher_mode->set_key(key.enc_key);
        cipher_mode->start(init_vector);

        Botan::secure_vector<uint8_t> dec_value(enc_value.begin(), enc_value.end());

        try {
            cipher_mode->finish(dec_value);
        } catch (...) {
            return std::unexpected(CryptoErrors::DecryptionError);
        }

        return dec_value;
    }

    std::expected<void, CryptoErrors> BitwardenCrypto::encryptAesCbc256_HmacSha256_B64(
        const Botan::secure_vector<uint8_t>& value, const ItemKey& key,
        Botan::secure_vector<uint8_t>& init_vector, Botan::secure_vector<uint8_t>& enc_value, 
        Botan::secure_vector<uint8_t>& mac) {
        
        Botan::AutoSeeded_RNG rng;
        init_vector = rng.random_vec(16);

        std::unique_ptr<Botan::Cipher_Mode> cipher =
            Botan::Cipher_Mode::create("AES-256/CBC/PKCS7", Botan::Cipher_Dir::Encryption);
        if (!cipher) {
            return std::unexpected(CryptoErrors::InvalidFamily);
        }
        cipher->set_key(key.enc_key.data(), key.enc_key.size());
        cipher->start(init_vector.data(), init_vector.size());

        enc_value = Botan::secure_vector<uint8_t>(value.begin(), value.end());
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
        mac = hmac->process(ivct);

        return {};
    }
}