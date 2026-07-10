#include "Folder.h"

namespace ClientWarden {
    Folder::Folder(Vault& vault, std::string uuid) : localVault(vault), isBeingCreated(false) {
        if (!logger) {
            logger = spdlog::stdout_color_mt("ClientWarden::Vault::Folder");
        }
        init = false;
        data["id"] = uuid;
        for (auto& folder : localVault.vaultData["folders"]) {
            if (!folder.contains("id")) {
                continue;
            }
            if (folder["id"].get<std::string>() == uuid) {
                data = folder;
                break;
            }
        }
        if (data.contains("name")) {
            init = true;
        }
    }

    Folder::Folder(Vault& vault) : localVault(vault), isBeingCreated(true) {
        if (!logger) {
            logger = spdlog::stdout_color_mt("ClientWarden::Vault::Folder");
        }
        data["id"] = uniqueGuid();
        data["name"] = localVault.Encrypt("", localVault.encKey, localVault.macKey);
        data["object"] = "folder";
        data["revisionDate"] = nullptr;

        init = true;
    }

    Folder::~Folder() {
        /*
        * TODO: Destruct
        */
    }

    Folder& Folder::SetName(std::string& name) {
        if (!init) return *this;
        data["name"] = localVault.Encrypt(name, localVault.encKey, localVault.macKey);
        OPENSSL_cleanse(name.data(), name.size());
        name.clear();
        return *this;
    }

    std::string Folder::Commit() {
        if (!init) return "";

        std::string idret;

        data["revisionDate"] = getBitwardenTime();
        if (isBeingCreated) {
            auto hr = localVault.OnlineCreateFolder(data["name"]);
            if (!hr) {
                logger->warn("Failed to add New Folder Online");
                localVault.storage.write("vault.json", localVault.vaultData.dump(2));
                return "";
            }
            nlohmann::json res = hr.value();
            if (res.contains("id") && res["id"].is_string()) {
                idret = res["id"];
            }
            localVault.vaultData["folders"].push_back(res);
            localVault.storage.write("vault.json", localVault.vaultData.dump(2));
            return idret;
        }

        auto& folders = localVault.vaultData["folders"];
        auto it = std::find_if(folders.begin(), folders.end(), [&](const nlohmann::json& folder) {
            return folder["id"] == data["id"];
        });

        if (it != folders.end()) {
            *it = data;
        }

        auto hr = localVault.OnlineRenameFolder(data["id"], data["name"]);
        localVault.storage.write("vault.json", localVault.vaultData.dump(2));
        
        return data["id"];
    }

    Folder& Folder::GetID(std::string& id) {
        id = data["id"];
        return *this;
    }

    void Folder::Delete() {
        if (!init) return;
        if (!isBeingCreated) {
            auto& folders = localVault.vaultData["folders"];
            auto it = std::find_if(folders.begin(), folders.end(), [&](const nlohmann::json& folder) {
                if (!folder.contains("id") || folder["id"].is_null()) return false;
                return folder["id"].get<std::string>() == data["id"].get<std::string>();
            });

            if (it != folders.end()) {
                folders.erase(it);
            }
            auto hr = localVault.OnlineDeleteFolder(data["id"]);
            if (hr != NetworkState::Success) {
                logger->warn("Failed to Delete Online Folder");
                localVault.vaultData["deletedFolders"].push_back(data["id"]);
            } 
        }
        localVault.storage.write("vault.json", localVault.vaultData.dump(2));
    }

    void Folder::Close() {
        if (!init) return;

        localVault.storage.write("vault.json", localVault.vaultData.dump(2));
    }

    Folder& Folder::GetName(std::string& name) {
        if (!init) return *this;
        if (!data.contains("name")) return *this;
        name = localVault.Decrypt(data["name"], localVault.encKey, localVault.macKey);
        return *this;
    }
}