#pragma once
#include <thread>
#include <nlohmann/json.hpp>
#include <botan/secmem.h>

#include "CWThread/CWThread.h"
#include "Clientwarden.h"

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
        std::recursive_mutex authDataMutex;
        std::recursive_mutex vaultDataMutex;
        std::recursive_mutex settingsDataMutex;

        std::shared_ptr<nlohmann::json> authData;
        std::shared_ptr<nlohmann::json> vaultData;
        std::shared_ptr<nlohmann::json> settingsData;

        std::shared_ptr<Botan::secure_vector<uint8_t>> internalKey;
        std::string masterPasswordHash;
        std::shared_ptr<Botan::secure_vector<uint8_t>> encKey;
        std::shared_ptr<Botan::secure_vector<uint8_t>> macKey;

        CWThread wssThread;
        CWThread refreshThread;
        CWThread connectivityThread;
    };
}