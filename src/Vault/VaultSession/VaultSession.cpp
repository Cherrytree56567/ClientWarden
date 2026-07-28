#include "VaultSession.h"

namespace ClientWarden {
    VaultSession::VaultSession() {
        authData = std::make_shared<nlohmann::json>();
        vaultData = std::make_shared<nlohmann::json>();
        settingsData = std::make_shared<nlohmann::json>();
        internalKey = std::make_shared<Botan::secure_vector<uint8_t>>();
        encKey = std::make_shared<Botan::secure_vector<uint8_t>>();
        macKey = std::make_shared<Botan::secure_vector<uint8_t>>();
    }

    VaultSession::~VaultSession() {
        /*
         * Background Threads should be stopped by Vault
        */
    }
}