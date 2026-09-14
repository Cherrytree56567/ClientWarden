#pragma once
#include <string>
#include <nlohmann/json.hpp>
#include "Clientwarden.h"

namespace ClientWarden {
    /*
     * 2026.6.0 - Removed Data Field
     * 2026.8.1 - Added Bank Account, Passport and Drivers License
    */
    class VaultFeatures {
    public:
        VaultFeatures();

        void determineVaultVersion(nlohmann::json vaultData);
        void determineVaultVersion(std::string networkingData);

        bool checkAbove26_8_1();
        bool checkAbove26_6_0();
        bool pendingNetworkCheck();

        std::optional<nlohmann::json> migrateVaultUpgrade(nlohmann::json data, bool t_26_6_0 = false, bool t_26_8_1 = false);
        std::optional<nlohmann::json> migrateVaultDowngrade(nlohmann::json data, bool below_26_6_0 = false, bool t_26_6_0 = false);
    private:
        std::vector<int> splitVersion(std::string version);
        int compareVersions(std::string v1, std::string v2);

        /*
         * By Default, we should use the oldest version possible to prevent
         * compat issues
        */
        bool _26_8_1 = false;
        bool _26_6_0 = false;
        bool p_networkCheck = true;
    };
}