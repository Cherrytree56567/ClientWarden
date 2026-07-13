#include "Folder.h"
#include "Vault.h"

namespace ClientWarden {
    Folder::Folder(Vault& vault, std::string uuid) : localVault(vault), isBeingCreated(false) {
        init = false;
        data["id"] = uuid;
        for (auto& folder : (*localVault.session.vaultData)["folders"]) {
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
        data["id"] = uniqueGuid();
        data["name"] = localVault.crypto.Encrypt("", *localVault.session.encKey, *localVault.session.macKey);
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
        data["name"] = localVault.crypto.Encrypt(name, *localVault.session.encKey, *localVault.session.macKey);
        OPENSSL_cleanse(name.data(), name.size());
        name.clear();
        return *this;
    }

    std::string Folder::Commit() {
        if (!init) return "";

        data["revisionDate"] = getBitwardenTime();
        if (isBeingCreated) {
            std::optional<nlohmann::json> o_result = localVault.CreateFolder(data["name"]);
            if (!o_result.has_value()) {
                logger->warn("Failed to add New Folder Online");
                localVault.storage.write("vault.json", localVault.session.vaultData->dump(2));
                return "";
            }

            nlohmann::json result = o_result.value();
            std::string returnID;

            if (result.contains("id") && result["id"].is_string()) {
                returnID = result["id"];
            }
            (*localVault.session.vaultData)["folders"].push_back(result);
            localVault.storage.write("vault.json", localVault.session.vaultData->dump(2));
            return returnID;
        }

        auto& folders = (*localVault.session.vaultData)["folders"];
        auto it = std::find_if(folders.begin(), folders.end(), [&](const nlohmann::json& folder) {
            return folder["id"] == data["id"];
        });

        if (it != folders.end()) {
            *it = data;
        }

        bool result = localVault.RenameFolder(data["id"], data["name"]);
        localVault.storage.write("vault.json", localVault.session.vaultData->dump(2));
        
        return data["id"];
    }

    Folder& Folder::GetID(std::string& id) {
        id = data["id"];
        return *this;
    }

    void Folder::Delete() {
        if (!init) return;
        if (!isBeingCreated) {
            auto& folders = (*localVault.session.vaultData)["folders"];
            auto it = std::find_if(folders.begin(), folders.end(), [&](const nlohmann::json& folder) {
                if (!folder.contains("id") || folder["id"].is_null()) return false;
                return folder["id"].get<std::string>() == data["id"].get<std::string>();
            });

            if (it != folders.end()) {
                folders.erase(it);
            }

            bool result = localVault.DeleteFolder(data["id"]);

            if (!result) {
                logger->warn("Failed to Delete Online Folder");
                (*localVault.session.vaultData)["deletedFolders"].push_back(data["id"]);
            } 
        }
        localVault.storage.write("vault.json", localVault.session.vaultData->dump(2));
    }

    void Folder::Close() {
        if (!init) return;

        localVault.storage.write("vault.json", localVault.session.vaultData->dump(2));
    }

    Folder& Folder::GetName(std::string& name) {
        if (!init) return *this;
        if (!data.contains("name")) return *this;
        name = localVault.crypto.DecryptAsStr(data["name"], *localVault.session.encKey, *localVault.session.macKey);
        return *this;
    }
}