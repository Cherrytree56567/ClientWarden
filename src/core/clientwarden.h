#pragma once
#include <botan/secmem.h>
#include <spdlog/spdlog.h>

namespace clientwarden {
    using ItemId = std::string;
    using Timestamp = std::chrono::system_clock::time_point;

    enum class Vendor {
        BitWarden
    };

    /**
     * @brief Used to specify which KDF Types can be used
     *
     * Can be expanded to support more KDF Types
    */
    enum class KDFType : uint8_t {
        PBKDF2_SHA256 = 0,
        Argon2ID = 1
    };

    /**
     * @brief Used to hold KDF Params
     * 
     * memory and parallel are optional and are only used for Argon2ID
    */
    struct KDFParams {
        KDFType type;
        int iterations = 0;
        int memory = 0;
        int parallel = 0;
    };

    /**
     * @brief Used to store Auth Data
     */
    struct AuthSession {
        Botan::secure_vector<uint8_t> access_token;
        Botan::secure_vector<uint8_t> refresh_token;
        Timestamp expires_at;
    };

    /**
     * @brief Used to store the biometric/auth keys
     */
    struct AuthKeys {
        Botan::secure_vector<uint8_t> internal_key;
        Botan::secure_vector<uint8_t> master_password_hash;

        void clear() {
            internal_key.clear();
            master_password_hash.clear();
        }
    };

    /**
     * @note From VaultWarden
     * https://github.com/dani-garcia/vaultwarden/blob/eb212e23fad88e6136723f43e5b73543fa7026d3/src/db/models/cipher.rs#L51
     * See (v2026.7.0): https://github.com/bitwarden/server/blob/5d4461aa42cadbacfef8fe2166c5453a5c52773a/src/Core/Vault/Enums/CipherType.cs
    */
    enum class ItemType {
        Login = 1,
        Card = 3,
        Identity = 4,
        Note = 2,
        SSHKey = 5,
        BankAccount = 6,
        DriversLicense = 7,
        Passport = 8,
        Generic = 0
    };

    /**
     * @brief Used to hold the encryption and verification keys.
    */
    struct ItemKey {
        Botan::secure_vector<uint8_t> enc_key;
        Botan::secure_vector<uint8_t> mac_key;

        void clear() {
            enc_key.clear();
            mac_key.clear();
        }
    };

    inline const std::string app_id = APP_ID;
    inline const std::string app_type = APP_TYPE;

    inline std::shared_ptr<spdlog::logger> g_logger = nullptr;
}