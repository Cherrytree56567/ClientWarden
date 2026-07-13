#include "VaultProfile.h"

namespace ClientWarden {
    VaultProfile::VaultProfile(std::shared_ptr<nlohmann::json> vaultData) : vaultData(vaultData) {
        
    }

    VaultProfile::~VaultProfile() {

    }

    std::string VaultProfile::profileName() {
        if (!vaultData->contains("profile")) {
            return "Unknown";
        }
        if (!(*vaultData)["profile"].contains("name")) {
            return "Unknown";
        }
        return (*vaultData)["profile"]["name"];
    }

    std::string VaultProfile::profileIcon() {
        // TODO
        return "";
    }
}