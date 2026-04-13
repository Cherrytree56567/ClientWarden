#pragma once
#include <string>
#include <vector>
#include <nlohmann/json.hpp>
#include "../CommonVault.h"
#include "../VaultUtils/VaultUtils.h"
#include "../Vault.h"

class LoginItem {
public:
    LoginItem(Vault& vault, std::string uuid); // Existing Item
    LoginItem(Vault& vault); // New Item
    ~LoginItem();

    LoginItem& SetName(std::string& name);
    LoginItem& SetUsername(std::string& username);
    LoginItem& SetPassword(std::string& password);
    LoginItem& SetTotp(std::string& totp);
    LoginItem& SetNotes(std::string& notes);
    LoginItem& SetFolder(std::string folder);
    LoginItem& RemoveFolder();
    LoginItem& AddWebsite(std::string& website);
    LoginItem& RemoveWebsite(std::string& website);
    LoginItem& AddField(CustomFieldType field, std::string& name, std::string& value);
    LoginItem& RemoveField(std::string& name);

    void Commit();
    void Delete();
private:
    bool isBeingCreated;
    nlohmann::json data;
    nlohmann::json fieldData;
    std::vector<uint8_t> itemEncKey;
    std::vector<uint8_t> itemMacKey;
    Vault& localVault;
};