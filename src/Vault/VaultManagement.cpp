#include "Vault.h"

void Vault::CreateLogin(LoginDetails& details) {
    auto [itemEncKey, itemMacKey] = generateEncMacKeys();

    std::vector<nlohmann::json> fields;
    std::vector<nlohmann::json> fieldsData;

    for (auto& field : details.customFields) {
        nlohmann::json fieldData;
        nlohmann::json DatafieldData;
        if (std::get<0>(field) == CustomFieldType::Text || std::get<0>(field) == CustomFieldType::Hidden || std::get<0>(field) == CustomFieldType::Checkbox) {
            fieldData["linkedId"] = nullptr;
            fieldData["name"] = Encrypt(std::get<1>(field), itemEncKey, itemMacKey);
            fieldData["type"] = std::get<0>(field);
            fieldData["value"] = Encrypt(std::get<2>(field), itemEncKey, itemMacKey);

            DatafieldData["Name"] = Encrypt(std::get<1>(field), itemEncKey, itemMacKey);
            DatafieldData["Type"] = std::get<0>(field);
            DatafieldData["Value"] = Encrypt(std::get<2>(field), itemEncKey, itemMacKey);
        } else if (std::get<0>(field) == CustomFieldType::Linked) {
            fieldData["value"] = nullptr;
            fieldData["name"] = Encrypt(std::get<1>(field), itemEncKey, itemMacKey);
            fieldData["type"] = 3;
            fieldData["linkedId"] = std::stoi(std::get<2>(field));

            DatafieldData["Name"] = Encrypt(std::get<1>(field), itemEncKey, itemMacKey);
            DatafieldData["Type"] = 3;
            DatafieldData["LinkedId"] = std::stoi(std::get<2>(field));
        }
        fields.push_back(fieldData);
        fieldsData.push_back(DatafieldData);
    }

    std::vector<nlohmann::json> uris;
    std::vector<nlohmann::json> urisData;
    std::string uri = "";

    if (details.websites.size() > 0) {
        uri = Encrypt(details.websites[0], itemEncKey, itemMacKey);
        for (auto website : details.websites) {
            nlohmann::json uriData;
            nlohmann::json dataJsonUri;
            uriData["match"] = nullptr;

            std::vector<uint8_t> websites(website.begin(), website.end());
            uriData["uri"] = InternalEncrypt(websites, itemEncKey, itemMacKey);
            dataJsonUri["Uri"] = InternalEncrypt(websites, itemEncKey, itemMacKey);
            OPENSSL_cleanse(websites.data(), websites.size());

            uriData["uriChecksum"] = getUriChecksum(website);
            dataJsonUri["UriChecksum"] = getUriChecksum(website);
            uris.push_back(uriData);
            urisData.push_back(dataJsonUri);
        }
    }

    std::string name = Encrypt(details.loginName, itemEncKey, itemMacKey);
    std::string username = Encrypt(details.username, itemEncKey, itemMacKey);
    std::string password = Encrypt(details.password, itemEncKey, itemMacKey);
    std::string totp = Encrypt(details.totp, itemEncKey, itemMacKey);
    std::string notes = Encrypt(details.notes, itemEncKey, itemMacKey);
    
    nlohmann::json data;
    data["archivedDate"] = nullptr;
    data["attachments"] = nullptr;
    data["card"] = nullptr;
    data["collectionIds"] = nlohmann::json::array();
    data["creationDate"] = getBitwardenTime();

    nlohmann::json dataJson;
    dataJson["Uris"] = nlohmann::json::array();
    for (auto& uriArr : urisData) {
        dataJson["Uris"].push_back(uriArr);
    }
    dataJson["Username"] = username;
    dataJson["Password"] = password;
    dataJson["Totp"] = totp;
    dataJson["Name"] = name;
    dataJson["Notes"] = notes;
    dataJson["Fields"] = nlohmann::json::array();
    for (auto& fieldData : fieldsData) {
        dataJson["Fields"].push_back(fieldData);
    }
    data["data"] = dataJson.dump();

    data["deletedDate"] = nullptr;
    data["edit"] = true;
    data["favorite"] = false;
    data["fields"] = nlohmann::json::array();
    for (auto& fieldData : fields) {
        data["fields"].push_back(fieldData);
    }
    data["folderId"] = nullptr;
    data["id"] = uniqueGuid();
    data["identity"] = nullptr;

    std::vector<uint8_t> mainKey(itemEncKey.begin(), itemEncKey.end());
    mainKey.insert(mainKey.end(), itemMacKey.begin(), itemMacKey.end());
    data["key"] = InternalEncrypt(mainKey, encKey, macKey);
    OPENSSL_cleanse(mainKey.data(), mainKey.size());

    data["login"] = nlohmann::json::object();

    data["login"]["autofillOnPageLoad"] = nullptr;
    data["login"]["fido2Credentials"] = nullptr;
    data["login"]["password"] = password;
    data["login"]["passwordRevisionDate"] = nullptr;
    data["login"]["totp"] = totp;
    data["login"]["uri"] = uri;
    data["login"]["uris"] = nlohmann::json::array();
    
    for (auto& uriData : uris) {
        data["login"]["uris"].push_back(uriData);
    }
    data["login"]["username"] = username;

    data["name"] = name;
    data["notes"] = notes;
    data["object"] = "cipherDetails";
    data["organizationId"] = nullptr;
    data["organizationUseTotp"] = false;
    data["passwordHistory"] = nullptr;
    data["permissions"] = nlohmann::json::object();
    data["permissions"]["delete"] = true;
    data["permissions"]["restore"] = true;
    data["reprompt"] = 0;
    data["revisionDate"] = nullptr;
    data["secureNote"] = nullptr;
    data["sshKey"] = nullptr;
    data["type"] = 1;
    data["viewPassword"] = true;
    OPENSSL_cleanse(itemEncKey.data(), itemEncKey.size());
    OPENSSL_cleanse(itemMacKey.data(), itemMacKey.size());
    
    OPENSSL_cleanse(details.loginName.data(), details.loginName.size());
    OPENSSL_cleanse(details.folderUUID.data(), details.folderUUID.size());
    OPENSSL_cleanse(details.username.data(), details.username.size());
    OPENSSL_cleanse(details.password.data(), details.password.size());
    OPENSSL_cleanse(details.totp.data(), details.totp.size());
    OPENSSL_cleanse(details.notes.data(), details.notes.size());
    for (auto& website : details.websites) {
        OPENSSL_cleanse(website.data(), website.size());
    }
    details.websites.clear();
    for (auto& field : details.customFields) {
        auto& s1 = std::get<1>(field);
        auto& s2 = std::get<2>(field);
        OPENSSL_cleanse(s1.data(), s1.size());
        OPENSSL_cleanse(s2.data(), s2.size());
    }
    details.customFields.clear();

    auto hr = OnlineNewItem(data);
    if (!hr) {
        spdlog::warn("Failed to Create Online Item");
        data["createdOffline"] = true;
    }

    vaultData["ciphers"].push_back(data);
    storage.write("vault.json", vaultData.dump(4));
    spdlog::info("{}", vaultData.dump(4));
}

void Vault::ModifyLogin(std::string uuid, LoginDetails& details) {
    nlohmann::json data;
    bool cipherFound = false;
    for (auto& cipher : vaultData["ciphers"]) {
        if (!cipher.contains("id")) {
            continue;
        }

        if (uuid == cipher["id"].get<std::string>()) {
            cipherFound = true;
            data = cipher;
        }
    } 
    /*
     * TODO: FINISH
    */
}