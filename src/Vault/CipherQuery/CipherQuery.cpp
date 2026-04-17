#include "CipherQuery.h"

namespace ClientWarden::Vault {
    CipherQuery::CipherQuery(Vault& vault) : localVault(vault) {
        logger = spdlog::stdout_color_mt("ClientWarden::Vault::CipherQuery");
        for (auto& cip : localVault.vaultData["ciphers"]) {
            ciphers.push_back(cip);
        }
    }

    CipherQuery::~CipherQuery() {
        /*
         * TODO: Destruct
        */
        ciphers.clear();
    }

    CipherQuery& CipherQuery::FilterByType(CipherType type) {
        for (auto it = ciphers.begin(); it != ciphers.end();) {
            if ((*it).contains("type") && (*it)["type"].get<int>() != static_cast<int>(type)) {
                it = ciphers.erase(it);
            } else {
                ++it;
            }
        }

        return *this;
    }

    CipherQuery& CipherQuery::FilterByCreationDate(std::time_t start, std::time_t end) {
        for (auto it = ciphers.begin(); it != ciphers.end();) {
            if (!(*it).contains("creationDate")) {
                ++it;
                continue;
            }

            std::time_t creation = BitwardenTime((*it)["creationDate"].get<std::string>());

            if (creation < start || creation > end) {
                it = ciphers.erase(it);
            } else {
                ++it;
            }
        }

        return *this;
    }

    CipherQuery& CipherQuery::FilterByRevisionDate(std::time_t start, std::time_t end) {
        for (auto it = ciphers.begin(); it != ciphers.end();) {
            if (!(*it).contains("revisionDate") || (*it)["revisionDate"].is_null()) {
                ++it;
                continue;
            }

            std::time_t revision = BitwardenTime((*it)["revisionDate"].get<std::string>());

            if (revision < start || revision > end) {
                it = ciphers.erase(it);
            } else {
                ++it;
            }
        }

        return *this;
    }

    CipherQuery& CipherQuery::FilterByDeletionDate(std::time_t start, std::time_t end) {
        for (auto it = ciphers.begin(); it != ciphers.end();) {
            if (!(*it).contains("deletedDate") || (*it)["deletedDate"].is_null()) {
                ++it;
                continue;
            }

            std::time_t deletion = BitwardenTime((*it)["deletedDate"].get<std::string>());

            if (deletion < start || deletion > end) {
                it = ciphers.erase(it);
            } else {
                ++it;
            }
        }

        return *this;
    }

    CipherQuery& CipherQuery::FilterByBinned() {
        for (auto it = ciphers.begin(); it != ciphers.end();) {
            if (!(*it).contains("deletedDate")) {
                it = ciphers.erase(it);
                continue;
            }

            if ((*it)["deletedDate"].is_null()) {
                it = ciphers.erase(it);
            } else {
                ++it;
            }
        }

        return *this;
    }

    CipherQuery& CipherQuery::FilterByUnbinned() {
        for (auto it = ciphers.begin(); it != ciphers.end();) {
            if (!(*it).contains("deletedDate")) {
                ++it;
                continue;
            }

            if (!(*it)["deletedDate"].is_null()) {
                it = ciphers.erase(it);
            } else {
                ++it;
            }
        }

        return *this;
    }

    CipherQuery& CipherQuery::FilterByFavorites() {
        for (auto it = ciphers.begin(); it != ciphers.end();) {
            if (!(*it).contains("favorite")) {
                it = ciphers.erase(it);
                continue;
            }

            if (!(*it)["favorite"].get<bool>()) {
                it = ciphers.erase(it);
            } else {
                ++it;
            }
        }

        return *this;
    }

    CipherQuery& CipherQuery::FilterByFolder(std::string folderUUID) {
        for (auto it = ciphers.begin(); it != ciphers.end();) {
            if (!(*it).contains("folderId")) {
                it = ciphers.erase(it);
                continue;
            }

            if ((*it)["folderId"].get<std::string>() != folderUUID) {
                it = ciphers.erase(it);
            } else {
                ++it;
            }
        }

        return *this;
    }

    CipherQuery& CipherQuery::FilterNameByRegex(std::string regex) {
        for (auto it = ciphers.begin(); it != ciphers.end();) {
            if (!(*it).contains("key")) {
                ++it;
                continue;
            }
            
            if (!(*it).contains("name")) {
                ++it;
                continue;
            }

            auto [itemEncKey, itemMacKey] = localVault.getKeysFromCipher((*it)["key"].get<std::string>());

            std::string name = localVault.Decrypt((*it)["name"].get<std::string>(), itemEncKey, itemMacKey);
            std::regex pattern(regex);

            if (!std::regex_match(name, pattern)) {
                OPENSSL_cleanse(name.data(), name.size());
                name.clear();
                it = ciphers.erase(it);
            } else {
                OPENSSL_cleanse(name.data(), name.size());
                name.clear();
                ++it;
            }
        }

        return *this;
    }

    std::vector<std::string> CipherQuery::Get() {
        std::vector<std::string> CipherIds;
        for (auto& cipher : ciphers) {
            if (!cipher.contains("id")) continue;
            CipherIds.push_back(cipher["id"].get<std::string>());
        }

        return CipherIds;
    }

    std::vector<std::pair<CipherType, std::string>> CipherQuery::GetCiphers() {
        std::vector<std::pair<CipherType, std::string>> CipherIds;
        for (auto& cipher : ciphers) {
            if (!cipher.contains("id")) continue;
            if (!cipher.contains("type")) continue;
            CipherIds.push_back({static_cast<CipherType>(cipher["type"].get<int>()), cipher["id"].get<std::string>()});
        }

        return CipherIds;
    }
}