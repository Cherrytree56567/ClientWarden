#include "Vault.h"

namespace ClientWarden::Vault {
    Vault::Vault() {
        spdlog::set_pattern("[%H:%M:%S] [%n] [%^---%L---%$] [thread %t] %v");
        logger = spdlog::stdout_color_mt("ClientWarden::Vault");
        vaultURL = "https://vault.bitwarden.com";
        mainURL = "https://bitwarden.com";
        apiURL = "https://api.bitwarden.com";
        iconURL = "https://icons.bitwarden.com";
    }

    Vault::~Vault() {
        stopRefreshThread();
    }

    /*
    * If an item is added locally, then it will have
    * a createdOffline Flag.
    * If an item is changed locally, then it will have
    * a higher revisionData
    * If an item is deleted locally, the id will be in 
    * a deletedCiphers key which stores an ID of all deleted
    * ciphers until they are deleted in the cloud.
    * If an item is added online, then it will be synced
    * If an item is modified online, then it will have a 
    * higher revision date and will be synced
    * If an item is deleted online, then the local one will not
    * have a createdOnline Flag, and so it will be deleted locally
    * First check if there are items in deletedCiphers
    *  - If there are, then delete them online
    * First Iterate through localVault:
    *  - If an item has createdOffline, then it will be synced to 
    *    online
    *  - Check if cipher exists online
    *  - If a cipher exists online, but the local revisionDate is newer
    *    - Update Online
    *  - If a cipher exists online, but the online revisionDate is newer
    *    - Overwrite Local
    *  - If a cipher doesnt exist online, and doesnt have createdOffline,
    *    - Delete Locally
    * Iterate Online Vault
    *  - If cipher exists online but not locally and Id isn't in deletedCiphers
    *    - Add Locally
    * Save Vault
    */
    NetworkState Vault::Sync() {
        if (!checkConnectivity()) {
            logger->warn("No Internet");
            return NetworkState::Failed;
        }
        if (!checkAccessTokenValidity()) {
            logger->warn("Invalid Access Token");
            return NetworkState::InvalidAccessToken;
        }

        httplib::Client client("https://vault.bitwarden.com");

        httplib::Headers headers = {
            { "authorization", "Bearer " + authData["accessString"].get<std::string>() },
            { "Accept", "application/json" },
            { "bitwarden-client-name", "web" },
            { "bitwarden-client-version", "2026.3.0" },
        };

        auto res = client.Get("/api/sync", headers);

        if (!res) {
            logger->error("sync request failed");
            return NetworkState::Failed;
        }
        if (res->status != 200) {
            logger->error("sync failed: {}", res->status);
            return NetworkState::Failed;
        }

        auto body = nlohmann::json::parse(res->body);

        if (!storage.exists("vault.json")) {
            storage.write("vault.json", body.dump(2));
            vaultData = body;
            return NetworkState::Success;
        }

        if (!vaultData.contains("deletedCiphers")) {
            vaultData["deletedCiphers"] = nlohmann::json::array();
        }
        if (!vaultData.contains("deletedFolders")) {
            vaultData["deletedFolders"] = nlohmann::json::array();
        }

        std::vector<std::string> pendingFolderDeletes;
        for (auto& id : vaultData["deletedFolders"]) {
            pendingFolderDeletes.push_back(id.get<std::string>());
        }

        auto& deletedFolders = vaultData["deletedFolders"];
        for (auto it = deletedFolders.begin(); it != deletedFolders.end();) {
            auto hr = OnlineDeleteFolder(it->get<std::string>());
            if (hr != NetworkState::Success) {
                logger->warn("Failed to Delete Online Folder");
                return hr;
            }
            it = deletedFolders.erase(it);
        }

        std::vector<std::string> localFolderIds;
        std::vector<std::string> removalFolderIds;

        for (auto& folder : vaultData["folders"]) {
            if (!folder.contains("id")) {
                continue;
            }

            localFolderIds.push_back(folder["id"]);

            nlohmann::json onlineFolder;
            bool foundOnlineFolder = false;

            for (auto& onl : body["folders"]) {
                if (onl.contains("id")) {
                    std::string onlineId = onl["id"];
                    std::string localId = folder["id"];
                    if (onlineId == localId) {
                        foundOnlineFolder = true;
                        onlineFolder = onl;
                        break;
                    }
                }
            }

            if (foundOnlineFolder) {
                std::time_t localRevDate = BitwardenTime(folder["revisionDate"]);
                std::time_t onlineRevDate = BitwardenTime(onlineFolder["revisionDate"]);

                if (localRevDate > onlineRevDate) {
                    /*
                    * Update Online
                    */
                    auto hr = OnlineRenameFolder(folder["id"], folder["name"]);
                    if (!hr) {
                        logger->warn("Failed to Update Online Folder");
                        return hr.error();
                    }
                    continue;
                } else if (onlineRevDate > localRevDate) {
                    /*
                    * Overwrite Local
                    */
                    folder = onlineFolder;
                    continue;
                }
            }

            if (!foundOnlineFolder) {
                /*
                * Delete Locally
                */
                removalFolderIds.push_back(folder["id"]);
                continue;
            }
        }

        auto& folders = vaultData["folders"];
        for (auto it = folders.begin(); it != folders.end();) {
            if (!it->contains("id") || !(*it)["id"].is_string()) {
                ++it;
                continue;
            }

            std::string id = (*it)["id"].get<std::string>();

            if (std::find(removalFolderIds.begin(), removalFolderIds.end(), id) != removalFolderIds.end()) {
                it = folders.erase(it);
            } else {
                ++it;
            }
        }

        for (auto& cipher : body["folders"]) {
            std::string id = cipher["id"].get<std::string>();
            if (std::find(localFolderIds.begin(), localFolderIds.end(), id) == localFolderIds.end()) {
                if (std::find(pendingFolderDeletes.begin(), pendingFolderDeletes.end(), id) == pendingFolderDeletes.end()) {
                    /*
                    * Add Locally
                    */
                    vaultData["folders"].push_back(cipher);
                }
            }
        }

        std::vector<std::string> pendingDeletes;
        for (auto& id : vaultData["deletedCiphers"]) {
            pendingDeletes.push_back(id.get<std::string>());
        }

        auto& deletedCiphers = vaultData["deletedCiphers"];
        for (auto it = deletedCiphers.begin(); it != deletedCiphers.end();) {
            auto hr = OnlineDeleteItem(it->get<std::string>());
            if (hr != NetworkState::Success) {
                logger->warn("Failed to Delete Online Item");
                return hr;
            }
            it = deletedCiphers.erase(it);
        }

        std::vector<std::string> localIds;
        std::vector<std::string> removalIds;

        for (auto& cipher : vaultData["ciphers"]) {
            if (!cipher.contains("id")) {
                continue;
            }

            localIds.push_back(cipher["id"]);

            if (cipher.contains("createdOffline")) {
                if (cipher["createdOffline"] == true) {
                    /*
                    * Sync Online
                    */
                    auto hr = OnlineNewItem(cipher);
                    if (!hr) {
                        logger->warn("Failed to Create Online Item");
                        return hr.error();
                    }
                    cipher["createdOffline"] = false;
                    continue;
                }
            }

            nlohmann::json onlineCipher;
            bool foundOnlineCipher = false;

            for (auto& onl : body["ciphers"]) {
                if (onl.contains("id")) {
                    std::string onlineId = onl["id"];
                    std::string localId = cipher["id"];
                    if (onlineId == localId) {
                        foundOnlineCipher = true;
                        onlineCipher = onl;
                        break;
                    }
                }
            }

            if (foundOnlineCipher) {
                std::time_t localRevDate = BitwardenTime(cipher["revisionDate"]);
                std::time_t onlineRevDate = BitwardenTime(onlineCipher["revisionDate"]);

                if (localRevDate > onlineRevDate) {
                    /*
                    * Update Online
                    */
                    auto hr = OnlineUpdateItem(cipher);
                    if (!hr) {
                        logger->warn("Failed to Create Online Item");
                        return hr.error();
                    }
                    continue;
                } else if (onlineRevDate > localRevDate) {
                    /*
                    * Overwrite Local
                    */
                    cipher = onlineCipher;
                    continue;
                }
            }

            if (!foundOnlineCipher) {
                if (cipher.contains("createdOffline")) {
                    if (cipher["createdOffline"] == true) {
                        continue;
                    }
                }
                /*
                * Delete Locally
                */
                removalIds.push_back(cipher["id"]);
                continue;
            }
        }

        auto& ciphers = vaultData["ciphers"];
        for (auto it = ciphers.begin(); it != ciphers.end();) {
            if (!it->contains("id") || !(*it)["id"].is_string()) {
                ++it;
                continue;
            }

            std::string id = (*it)["id"].get<std::string>();

            if (std::find(removalIds.begin(), removalIds.end(), id) != removalIds.end()) {
                it = ciphers.erase(it);
            } else {
                ++it;
            }
        }

        for (auto& cipher : body["ciphers"]) {
            std::string id = cipher["id"].get<std::string>();
            if (std::find(localIds.begin(), localIds.end(), id) == localIds.end()) {
                if (std::find(pendingDeletes.begin(), pendingDeletes.end(), id) == pendingDeletes.end()) {
                    /*
                    * Add Locally
                    */
                    vaultData["ciphers"].push_back(cipher);
                }
            }
        }

        storage.write("vault.json", vaultData.dump(2));

        return NetworkState::Success;
    }
}