#pragma once
#include <thread>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/basic_file_sink.h>

namespace ClientWarden {
    /*
     * Vault Session will contain background threads
     * as well as the secure info like masterPasswordHash
     * or the internelKey
    */
    class VaultSession {
    public:
        VaultSession();
        ~VaultSession();

    public:
        std::shared_ptr<nlohmann::json> authData;
        std::shared_ptr<nlohmann::json> vaultData;
        std::shared_ptr<nlohmann::json> settingsData;

        Botan::secure_vector<uint8_t> internalKey;
        std::string masterPasswordHash;
        std::shared_ptr<Botan::secure_vector<uint8_t>> encKey;
        std::shared_ptr<Botan::secure_vector<uint8_t>> macKey;

        CWThread wssThread;
        CWThread refreshThread;
        CWThread connectivityThread;

        inline static std::shared_ptr<spdlog::logger> logger;
    };
}