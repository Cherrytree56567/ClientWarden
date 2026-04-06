#include "Vault.h"

void Vault::newItem(nlohmann::json data) {/*
    httplib::Client client("https://vault.bitwarden.com");

    httplib::Headers headers = {
        { "authorization", "Bearer " + jsonData["accessString"].get<std::string>() },
        { "Content-Type", "application/json" },
        { "bitwarden-client-name", "web" },
        { "bitwarden-client-version", "2026.3.0" },
    };

    auto res = client.Post("/api/ciphers", headers, "{\"email\":\"" + email + "\"}", "application/json");

    if (!res) {
        spdlog::error("newItem request failed");
        throw std::runtime_error("newItem request failed");
    }
    if (res->status != 200) {
        spdlog::error("newItem failed: {}", res->status);
        throw std::runtime_error("newItem failed: " + std::to_string(res->status));
    }

    auto body = nlohmann::json::parse(res->body);*/
}

void Vault::updateItem(nlohmann::json data) {
    
}

void Vault::deleteItem(std::string uuid) {
    
}

void Vault::addAttachment(std::string uuid, std::string file) {
    
}

void Vault::removeAttachment(std::string uuid, std::string attachmentID) {
    
}

std::string Vault::downloadAttachment(std::string uuid, std::string attachmentID) {
    return "";
}

void Vault::createFolder(std::string folderName) {
    
}

void Vault::renameFolder(std::string folderUUID, std::string folderName) {
    
}

void Vault::deleteFolder(std::string folderUUID) {
    
}

std::string Vault::downloadIcon(std::string url) {
    return "";
}