#pragma once
#include <botan/secmem.h>
#include <spdlog/spdlog.h>

namespace clientwarden {
    enum class Vendor {
        BitWarden
    };

    /**
     * @brief Used to specify which KDF Types can be used
     *
     * Can be expanded to support more KDF Types
    */
    enum class KDFType {
        PBKDF2_SHA256,
        Argon2ID
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
        std::chrono::seconds expires_in;
    };

    /**
     * @brief Used to store the biometric/auth keys
     */
    struct AuthKeys {
        Botan::secure_vector<uint8_t> internal_key;
        Botan::secure_vector<uint8_t> master_password_hash;
    };

    const std::string app_id = APP_ID;

    using ItemId = std::string;

    inline std::shared_ptr<spdlog::logger> g_logger = nullptr;
}