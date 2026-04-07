#include "Vault.h"

nlohmann::json Vault::InternalNewItem(nlohmann::json encryptedData) {
    httplib::Client client("https://vault.bitwarden.com");

    httplib::Headers headers = {
        { "authorization", "Bearer " + jsonData["accessString"].get<std::string>() },
        { "Content-Type", "application/json" },
        { "bitwarden-client-name", "web" },
        { "bitwarden-client-version", "2026.3.0" },
    };

    auto res = client.Post("/api/ciphers", headers, encryptedData.dump(), "application/json");

    if (!res) {
        spdlog::error("newItem request failed");
        throw std::runtime_error("newItem request failed");
    }
    if (res->status != 200) {
        spdlog::error("newItem failed: {}", res->status);
        throw std::runtime_error("newItem failed: " + std::to_string(res->status));
    }

    auto body = nlohmann::json::parse(res->body);
    return body;
}

nlohmann::json Vault::InternalUpdateItem(nlohmann::json encryptedData) {
    if (!encryptedData.contains("id")) {
        return nlohmann::json();
    }
    httplib::Client client("https://vault.bitwarden.com");

    httplib::Headers headers = {
        { "authorization", "Bearer " + jsonData["accessString"].get<std::string>() },
        { "Content-Type", "application/json" },
        { "bitwarden-client-name", "web" },
        { "bitwarden-client-version", "2026.3.0" },
    };

    auto res = client.Put("/api/ciphers/" + encryptedData["id"].get<std::string>(), headers, encryptedData.dump(), "application/json");

    if (!res) {
        spdlog::error("updateItem request failed");
        throw std::runtime_error("updateItem request failed");
    }
    if (res->status != 200) {
        spdlog::error("updateItem failed: {}", res->status);
        throw std::runtime_error("updateItem failed: " + std::to_string(res->status));
    }

    auto body = nlohmann::json::parse(res->body);
    return body;
}

void Vault::InternalDeleteItem(std::string uuid) {
    httplib::Client client("https://vault.bitwarden.com");

    httplib::Headers headers = {
        { "authorization", "Bearer " + jsonData["accessString"].get<std::string>() },
        { "Content-Type", "application/json" },
        { "bitwarden-client-name", "web" },
        { "bitwarden-client-version", "2026.3.0" },
    };

    auto res = client.Delete("/api/ciphers/" + uuid, headers);

    if (!res) {
        spdlog::error("deleteItem request failed");
        throw std::runtime_error("deleteItem request failed");
    }
    if (res->status != 200) {
        spdlog::error("deleteItem failed: {}", res->status);
        throw std::runtime_error("deleteItem failed: " + std::to_string(res->status));
    }
}

nlohmann::json Vault::InternalAddAttachment(std::string uuid, std::string encryptedFileContents, std::string encryptedFileName) {
    spdlog::error("Unsupported: Add Attachment");
    return nlohmann::json();
}

void Vault::InternalRemoveAttachment(std::string uuid, std::string attachmentID) {
    spdlog::error("Unsupported: Remove Attachment");
}

std::string Vault::InternalDownloadAttachment(std::string uuid, std::string attachmentID) {
    spdlog::error("Unsupported: Download Attachment");
    return "";
}

nlohmann::json Vault::InternalCreateFolder(std::string encryptedFolderName) {
    httplib::Client client("https://vault.bitwarden.com");

    httplib::Headers headers = {
        { "authorization", "Bearer " + jsonData["accessString"].get<std::string>() },
        { "Content-Type", "application/json" },
        { "bitwarden-client-name", "web" },
        { "bitwarden-client-version", "2026.3.0" },
    };

    auto res = client.Post("/api/folders", headers, "{\"name\": \"" + encryptedFolderName + "\"}", "application/json");

    if (!res) {
        spdlog::error("createFolder request failed");
        throw std::runtime_error("createFolder request failed");
    }
    if (res->status != 200) {
        spdlog::error("createFolder failed: {}", res->status);
        throw std::runtime_error("createFolder failed: " + std::to_string(res->status));
    }

    auto body = nlohmann::json::parse(res->body);
    return body;
}

nlohmann::json Vault::InternalRenameFolder(std::string folderUUID, std::string encryptedFolderName) {
    httplib::Client client("https://vault.bitwarden.com");

    httplib::Headers headers = {
        { "authorization", "Bearer " + jsonData["accessString"].get<std::string>() },
        { "Content-Type", "application/json" },
        { "bitwarden-client-name", "web" },
        { "bitwarden-client-version", "2026.3.0" },
    };

    auto res = client.Put("/api/folders/" + folderUUID, headers, "{\"name\": \"" + encryptedFolderName + "\"}", "application/json");

    if (!res) {
        spdlog::error("renameFolder request failed");
        throw std::runtime_error("renameFolder request failed");
    }
    if (res->status != 200) {
        spdlog::error("renameFolder failed: {}", res->status);
        throw std::runtime_error("renameFolder failed: " + std::to_string(res->status));
    }

    auto body = nlohmann::json::parse(res->body);
    return body;
}

void Vault::InternalDeleteFolder(std::string folderUUID) {
    httplib::Client client("https://vault.bitwarden.com");

    httplib::Headers headers = {
        { "authorization", "Bearer " + jsonData["accessString"].get<std::string>() },
        { "Content-Type", "application/json" },
        { "bitwarden-client-name", "web" },
        { "bitwarden-client-version", "2026.3.0" },
    };

    auto res = client.Delete("/api/folders/" + folderUUID, headers);

    if (!res) {
        spdlog::error("deleteFolder request failed");
        throw std::runtime_error("deleteFolder request failed");
    }
    if (res->status != 200) {
        spdlog::error("deleteFolder failed: {}", res->status);
        throw std::runtime_error("deleteFolder failed: " + std::to_string(res->status));
    }
}

std::vector<uint8_t> Vault::InternalDownloadIcon(std::string url) {
    httplib::Client client("https://icons.bitwarden.com");

    auto res = client.Get("/" + url + "/icon.png");

    if (!res) {
        spdlog::error("downloadIcon request failed");
        throw std::runtime_error("downloadIcon request failed");
    }
    if (res->status != 200) {
        spdlog::error("downloadIcon failed: {}", res->status);
        throw std::runtime_error("downloadIcon failed: " + std::to_string(res->status));
    }

    return std::vector<uint8_t>(res->body.begin(), res->body.end());
}