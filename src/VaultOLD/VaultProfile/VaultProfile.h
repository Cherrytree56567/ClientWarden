#pragma once
#include <string>
#include <nlohmann/json.hpp>

#include "Clientwarden.h"

namespace ClientWarden {
    class VaultProfile {
    public:
        VaultProfile(std::shared_ptr<nlohmann::json> vaultData);
        ~VaultProfile();

        std::string profileName();
        std::string profileIcon();

    private:
        std::shared_ptr<nlohmann::json> vaultData;
    };
}