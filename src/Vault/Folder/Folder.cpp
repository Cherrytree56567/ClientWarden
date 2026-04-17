#include "Folder.h"

namespace ClientWarden::Vault {
    Folder::Folder(Vault& vault, std::string uuid) : localVault(vault), isBeingCreated(false) {
        logger = spdlog::stdout_color_mt("ClientWarden::Vault::Folder");
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
        logger = spdlog::stdout_color_mt("ClientWarden::Vault::Folder");
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

    void Folder::Commit() {
        if (!init) return;

        data["revisionDate"] = getBitwardenTime();
        if (isBeingCreated) {
            auto hr = localVault.OnlineCreateFolder(data["name"]);
            if (!hr) {
                spdlog::warn("Failed to add New Folder Online");
                localVault.storage.write("vault.json", localVault.vaultData.dump(2));
                return;
            }
            nlohmann::json res = hr.value();
            localVault.vaultData["folders"].push_back(res);
            localVault.storage.write("vault.json", localVault.vaultData.dump(2));
            return;
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
                spdlog::warn("Failed to Delete Online Folder");
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