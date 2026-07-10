#pragma once
#include <string>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/basic_file_sink.h>

namespace ClientWarden {
    class VaultProfile {
    public:
        VaultProfile(nlohmann::json vaultData);
        ~VaultProfile();

        std::string profileName();
        std::string profileIcon();

    private:
        nlohmann::json vaultData;
        inline static std::shared_ptr<spdlog::logger> logger;
    };
}