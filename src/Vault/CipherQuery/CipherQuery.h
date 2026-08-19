#pragma once
#include <string>
#include <vector>
#include <regex>
#include <nlohmann/json.hpp>
#include <botan/secmem.h>

#include "Clientwarden.h"
#include "VaultUtils/VaultUtils.h"

namespace ClientWarden {
    class Vault;

    class CipherQuery {
    public:
        CipherQuery(Vault& vault);
        ~CipherQuery();

        CipherQuery& FilterByType(CipherType type);
        CipherQuery& FilterByCreationDate(std::time_t start, std::time_t end);
        CipherQuery& FilterByRevisionDate(std::time_t start, std::time_t end);
        CipherQuery& FilterByDeletionDate(std::time_t start, std::time_t end);
        CipherQuery& FilterByBinned();
        CipherQuery& FilterByUnbinned();
        CipherQuery& FilterByArchived();
        CipherQuery& FilterByUnarchived();
        CipherQuery& FilterByFavorites();
        CipherQuery& FilterByFolder(std::string folderUUID);
        CipherQuery& FilterNameByRegex(std::string regex);

        std::vector<std::string> Get();
        std::vector<std::pair<CipherType, std::string>> GetCiphers();
    private:
        bool init;
        std::vector<nlohmann::json> ciphers;
        Vault& localVault;
    };
}