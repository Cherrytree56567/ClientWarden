#pragma once
#include <string>
#include <vector>
#include <nlohmann/json.hpp>
#include "../CommonVault.h"
#include "../VaultUtils/VaultUtils.h"
#include "../Vault.h"

namespace ClientWarden::Vault {
    class Folder {
    public:
        Folder(Vault& vault, std::string uuid); // Existing Folder
        Folder(Vault& vault); // New Folder
        ~Folder();

        Folder& SetName(std::string& name);
        Folder& GetName(std::string& name);

        void Commit();
        void Delete();
        void Close();
    private:
        bool isBeingCreated;
        bool init;
        nlohmann::json data;
        Vault& localVault;
    };
}