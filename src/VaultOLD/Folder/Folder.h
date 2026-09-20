#pragma once
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

#include "Clientwarden.h"

namespace ClientWarden {
    class Vault;

    class Folder {
    public:
        Folder(Vault& vault, std::string uuid); // Existing Folder
        Folder(Vault& vault); // New Folder
        ~Folder();

        Folder& SetName(std::string& name);
        Folder& GetName(std::string& name);

        Folder& GetID(std::string& id);

        std::string Commit();
        void Delete();
        void Close();
    private:
        bool isBeingCreated;
        bool init;
        nlohmann::json data;
        Vault& localVault;
    };
}