#include "VaultFeatures.h"

namespace ClientWarden {
    VaultFeatures::VaultFeatures() {

    }

    std::vector<int> VaultFeatures::splitVersion(std::string version) {
        std::vector<int> p_version;
        std::stringstream ss_version(version);
        std::string s_version;

        while (std::getline(ss_version, s_version, '.')) {
            p_version.push_back(std::stoi(s_version));
        }

        return p_version;
    }
    
    int VaultFeatures::compareVersions(std::string v1, std::string v2) {
        std::vector<int> s_v1 = splitVersion(v1);
        std::vector<int> s_v2 = splitVersion(v2);

        size_t m_length = std::max(s_v1.size(), s_v2.size());

        for (size_t i = 0; i < m_length; ++i) {
            int p_v1 = (i < s_v1.size()) ? s_v1[i] : 0;
            int p_v2 = (i < s_v2.size()) ? s_v2[i] : 0;

            if (p_v1 != p_v2) {
                return p_v1 - p_v2;
            }
        }

        return 0;
    }

    void VaultFeatures::determineVaultVersion(nlohmann::json vaultData) {
        if (!vaultData.contains("ciphers") || !vaultData["ciphers"].is_array() || vaultData["ciphers"].empty()) {
            return;
        }

        /*
         * First, we should check if all items in the vault have
         * a data value, if it does then we know that it has to be a version > 2026.6.0
        */
        bool u_data = true;

        for (const auto& cipher : vaultData["ciphers"]) {
            bool h_dataField = cipher.contains("data");

            if (!h_dataField) {
                u_data = false;
            }
        }

        /*
         * Then, we can check if every single one has a bankAccount, driversLicense
         * and passport field.
        */
        bool u_26_8_1 = true;

        for (const auto& cipher : vaultData["ciphers"]) {
            bool h_bankAccountField = cipher.contains("bankAccount");
            bool h_driversLicenseField = cipher.contains("driversLicense");
            bool h_passportField = cipher.contains("passport");

            if (!h_bankAccountField || !h_driversLicenseField || !h_passportField) {
                u_26_8_1 = false;
            }
        }

        if (!_26_6_0) {
            _26_6_0 = u_data;
        }

        if (!_26_8_1) {
            _26_8_1 = u_26_8_1;
        }
    }

    void VaultFeatures::determineVaultVersion(std::string networkingData) {
        if (nlohmann::json::accept(networkingData)) {
            nlohmann::json data = nlohmann::json::parse(networkingData);

            if (data.contains("version") && data["version"].is_string()) {
                if (compareVersions(data["version"], "2026.6.0") >= 0) {
                    _26_6_0 = true;
                }

                if (compareVersions(data["version"], "2026.8.1") >= 0) {
                    _26_8_1 = true;
                }

                p_networkCheck = false;
            }
        }
    }

    bool VaultFeatures::checkAbove26_8_1() {
        return _26_8_1;
    }

    bool VaultFeatures::checkAbove26_6_0() {
        return _26_6_0 || _26_6_0;
    }

    bool VaultFeatures::pendingNetworkCheck() {
        return p_networkCheck;
    }

    std::optional<nlohmann::json> migrateVaultUpgrade(nlohmann::json data, bool t_26_6_0, bool t_26_8_1) {
        if (!data.contains("ciphers") || !data["ciphers"].is_array()) {
            return std::nullopt;
        }

        logger->warn("Upgrading Vault");
        
        for (auto& cipher : data["ciphers"]) {
            if (t_26_6_0 || t_26_8_1) {
                /*
                 * Remove all data tags
                */
                cipher.erase("data");
            }

            if (t_26_8_1) {
                /*
                 * Add's bankAccount, Drivers License and Passport
                */
                cipher["bankAccount"] = nullptr;
                cipher["driversLicense"] = nullptr;
                cipher["passport"] = nullptr;
            }
        }

        return data;
    }

    std::optional<nlohmann::json> migrateVaultDowngrade(nlohmann::json data, bool below_26_6_0, bool t_26_6_0) {
        if (!data.contains("ciphers") || !data["ciphers"].is_array()) {
            return std::nullopt;
        }

        logger->warn("Downgrade is not officially supported");
        
        for (auto& cipher : data["ciphers"]) {
            if (below_26_6_0) {
                /*
                 * Add data tags
                 * TODO: Properly Add
                */
            }

            if (t_26_6_0) {
                /*
                 * Remove's bankAccount, Drivers License and Passport
                */
                cipher.erase("bankAccount");
                cipher.erase("driversLicense");
                cipher.erase("passport");
            }
        }

        return data;
    }
}