#include "Vault.h"

NetworkState Vault::preLogin(std::string& email) {
    httplib::Client client(vaultURL);

    httplib::Headers headers = {
        { "Content-Type", "application/json" },
        { "bitwarden-client-name", "web" },
        { "bitwarden-client-version", "2026.3.0" },
    };

    auto res = client.Post("/identity/accounts/prelogin", headers, "{\"email\":\"" + email + "\"}", "application/json");

    if (!res) {
        spdlog::error("preLogin request failed");
        return NetworkState::Failed;
    }
    if (res->status != 200) {
        spdlog::error("preLogin failed: {}, {}", res->status, res->body);
        return NetworkState::Failed;
    }

    auto body = nlohmann::json::parse(res->body);
    authData["kdfIterations"] = body["kdfIterations"];
    authData["salt"] = body["salt"];
    authData["email"] = email;

    return NetworkState::Success;
}

AuthState Vault::getToken() {
    httplib::Client client(vaultURL);

    client.set_default_headers({
        { "Accept", "application/json" },
        { "Content-Type", "application/x-www-form-urlencoded; charset=utf-8" },
        { "bitwarden-client-name", "web" },
        { "bitwarden-client-version", "2026.3.0" },
    });

    httplib::Params data;
    data.emplace("grant_type", "password");
    data.emplace("username", authData["email"]);
    data.emplace("password", masterPasswordHash);
    data.emplace("scope", "api offline_access");
    data.emplace("client_id", "web");
    data.emplace("deviceType", "10");
    data.emplace("deviceIdentifier", uniqueGuid());
    data.emplace("deviceName", "firefox");
    
    auto res = client.Post("/identity/connect/token", data);

    if (res->status == 400) {
        auto body = nlohmann::json::parse(res->body);
        if (body["error_description"] == "Two factor required.") {
            spdlog::warn("Needs Two Factor Auth.");
            return AuthState::NeedsTOTP;
        } else if (body["error_description"] == "New device verification required") {
            spdlog::warn("Needs New Device Verification.");
            return AuthState::NeedsEmailVerification;
        }
    }

    if (!res) {
        spdlog::error("getToken request failed");
        return AuthState::Failed;
    }
    if (res->status != 200) {
        spdlog::error("getToken failed: {}", res->status);
        return AuthState::Failed;
    }

    auto body = nlohmann::json::parse(res->body);
    authData["accessString"] = body["access_token"];
    authData["refreshToken"] = body["refresh_token"];
    authData["expiresIn"] = body["expires_in"];

    std::time_t now = std::time(nullptr) + authData["expiresIn"].get<int>();
    std::tm* localTime = std::localtime(&now);

    std::ostringstream oss;
    oss << std::put_time(localTime, "%Y-%m-%d %H:%M:%S");
    authData["needsRefreshTime"] = oss.str();

    storage.write("data.json", authData.dump(2));

    return AuthState::Authenticated;
}

AuthState Vault::getTokenWTotp(std::string& totp) {
    httplib::Client client(vaultURL);

    client.set_default_headers({
        { "Accept", "application/json" },
        { "Content-Type", "application/x-www-form-urlencoded; charset=utf-8" },
        { "bitwarden-client-name", "web" },
        { "bitwarden-client-version", "2026.3.0" },
    });

    httplib::Params data;
    data.emplace("grant_type", "password");
    data.emplace("username", authData["email"]);
    data.emplace("password", masterPasswordHash);
    data.emplace("scope", "api offline_access");
    data.emplace("client_id", "web");
    data.emplace("deviceType", "10");
    data.emplace("deviceIdentifier", uniqueGuid());
    data.emplace("deviceName", "firefox");
    data.emplace("twoFactorToken", totp);
    data.emplace("twoFactorProvider", "0");
    data.emplace("twoFactorRemember", "0");
    
    auto res = client.Post("/identity/connect/token", data);

    if (!res) {
        spdlog::error("getToken request failed");
        return AuthState::Failed;
    }
    if (res->status != 200) {
        spdlog::error("getToken failed: {}", res->status);
        return AuthState::Failed;
    }

    auto body = nlohmann::json::parse(res->body);
    authData["accessString"] = body["access_token"];
    authData["refreshToken"] = body["refresh_token"];
    authData["expiresIn"] = body["expires_in"];

    std::time_t now = std::time(nullptr) + authData["expiresIn"].get<int>();
    std::tm* localTime = std::localtime(&now);

    std::ostringstream oss;
    oss << std::put_time(localTime, "%Y-%m-%d %H:%M:%S");
    authData["needsRefreshTime"] = oss.str();

    storage.write("data.json", authData.dump(2));

    return AuthState::Authenticated;
}

AuthState Vault::getTokenWDeviceVerify(std::string& code) {
    httplib::Client client(vaultURL);

    client.set_default_headers({
        { "Accept", "application/json" },
        { "Content-Type", "application/x-www-form-urlencoded; charset=utf-8" },
        { "bitwarden-client-name", "web" },
        { "bitwarden-client-version", "2026.3.0" },
    });

    httplib::Params data;
    data.emplace("grant_type", "password");
    data.emplace("username", authData["email"]);
    data.emplace("password", masterPasswordHash);
    data.emplace("scope", "api offline_access");
    data.emplace("client_id", "web");
    data.emplace("deviceType", "10");
    data.emplace("deviceIdentifier", uniqueGuid());
    data.emplace("deviceName", "firefox");
    data.emplace("newDeviceOtp", code);
    
    auto res = client.Post("/identity/connect/token", data);

    if (!res) {
        spdlog::error("getToken request failed");
        return AuthState::Failed;
    }
    if (res->status != 200) {
        spdlog::error("getToken failed: {}", res->status);
        return AuthState::Failed;
    }

    auto body = nlohmann::json::parse(res->body);
    authData["accessString"] = body["access_token"];
    authData["refreshToken"] = body["refresh_token"];
    authData["expiresIn"] = body["expires_in"];

    std::time_t now = std::time(nullptr) + authData["expiresIn"].get<int>();
    std::tm* localTime = std::localtime(&now);

    std::ostringstream oss;
    oss << std::put_time(localTime, "%Y-%m-%d %H:%M:%S");
    authData["needsRefreshTime"] = oss.str();

    storage.write("data.json", authData.dump(2));

    return AuthState::Authenticated;
}

bool Vault::checkConnectivity() {
    httplib::Client client(apiURL);
    client.set_connection_timeout(1);
    auto res = client.Get("/alive");
    return res && res->status == 200;
}

bool Vault::checkAccessTokenValidity() {
    httplib::Client client(apiURL);
    client.set_connection_timeout(3);
    
    httplib::Headers headers = {
        {"Authorization", "Bearer " + authData["accessString"].get<std::string>()}
    };
    
    auto res = client.Get("/api/accounts/profile", headers);
    return res && res->status != 401;
}

std::expected<nlohmann::json, NetworkState> Vault::OnlineNewItem(nlohmann::json encryptedData) {
    httplib::Client client(vaultURL);

    httplib::Headers headers = {
        { "authorization", "Bearer " + authData["accessString"].get<std::string>() },
        { "Content-Type", "application/json" },
        { "bitwarden-client-name", "web" },
        { "bitwarden-client-version", "2026.3.0" },
    };

    auto res = client.Post("/api/ciphers", headers, encryptedData.dump(), "application/json");

    if (!res) {
        spdlog::error("newItem request failed");
        return std::unexpected(NetworkState::Failed);
    }
    if (res->status != 200) {
        spdlog::error("newItem failed: {}", res->status);
        return std::unexpected(NetworkState::Failed);
    }

    auto body = nlohmann::json::parse(res->body);
    return body;
}

std::expected<nlohmann::json, NetworkState> Vault::OnlineUpdateItem(nlohmann::json encryptedData) {
    if (!encryptedData.contains("id")) {
        return nlohmann::json();
    }
    httplib::Client client(vaultURL);

    httplib::Headers headers = {
        { "authorization", "Bearer " + authData["accessString"].get<std::string>() },
        { "Content-Type", "application/json" },
        { "bitwarden-client-name", "web" },
        { "bitwarden-client-version", "2026.3.0" },
    };

    auto res = client.Put("/api/ciphers/" + encryptedData["id"].get<std::string>(), headers, encryptedData.dump(), "application/json");

    if (!res) {
        spdlog::error("updateItem request failed");
        return std::unexpected(NetworkState::Failed);
    }
    if (res->status != 200) {
        spdlog::error("updateItem failed: {}", res->status);
        return std::unexpected(NetworkState::Failed);
    }

    auto body = nlohmann::json::parse(res->body);
    return body;
}

NetworkState Vault::OnlineDeleteItem(std::string uuid) {
    httplib::Client client(vaultURL);

    httplib::Headers headers = {
        { "authorization", "Bearer " + authData["accessString"].get<std::string>() },
        { "Content-Type", "application/json" },
        { "bitwarden-client-name", "web" },
        { "bitwarden-client-version", "2026.3.0" },
    };

    auto res = client.Delete("/api/ciphers/" + uuid, headers);

    if (!res) {
        spdlog::error("deleteItem request failed");
        return NetworkState::Failed;
    }
    if (res->status != 200) {
        spdlog::error("deleteItem failed: {}", res->status);
        return NetworkState::Failed;
    }
    return NetworkState::Success;
}

std::expected<nlohmann::json, NetworkState> Vault::OnlineAddAttachment(std::string uuid, std::string encryptedFileContents, std::string encryptedFileName) {
    spdlog::error("Unsupported: Add Attachment");
    return std::unexpected(NetworkState::NotImpl);
}

NetworkState Vault::OnlineRemoveAttachment(std::string uuid, std::string attachmentID) {
    spdlog::error("Unsupported: Remove Attachment");
    return NetworkState::NotImpl;
}

std::expected<std::string, NetworkState> Vault::OnlineDownloadAttachment(std::string uuid, std::string attachmentID) {
    spdlog::error("Unsupported: Download Attachment");
    return std::unexpected(NetworkState::NotImpl);
}

std::expected<nlohmann::json, NetworkState> Vault::OnlineCreateFolder(std::string encryptedFolderName) {
    httplib::Client client(vaultURL);

    httplib::Headers headers = {
        { "authorization", "Bearer " + authData["accessString"].get<std::string>() },
        { "Content-Type", "application/json" },
        { "bitwarden-client-name", "web" },
        { "bitwarden-client-version", "2026.3.0" },
    };

    auto res = client.Post("/api/folders", headers, "{\"name\": \"" + encryptedFolderName + "\"}", "application/json");

    if (!res) {
        spdlog::error("createFolder request failed");
        return std::unexpected(NetworkState::Failed);
    }
    if (res->status != 200) {
        spdlog::error("createFolder failed: {}", res->status);
        return std::unexpected(NetworkState::Failed);
    }

    auto body = nlohmann::json::parse(res->body);
    return body;
}

std::expected<nlohmann::json, NetworkState> Vault::OnlineRenameFolder(std::string folderUUID, std::string encryptedFolderName) {
    httplib::Client client(vaultURL);

    httplib::Headers headers = {
        { "authorization", "Bearer " + authData["accessString"].get<std::string>() },
        { "Content-Type", "application/json" },
        { "bitwarden-client-name", "web" },
        { "bitwarden-client-version", "2026.3.0" },
    };

    auto res = client.Put("/api/folders/" + folderUUID, headers, "{\"name\": \"" + encryptedFolderName + "\"}", "application/json");

    if (!res) {
        spdlog::error("renameFolder request failed");
        return std::unexpected(NetworkState::Failed);
    }
    if (res->status != 200) {
        spdlog::error("renameFolder failed: {}", res->status);
        return std::unexpected(NetworkState::Failed);
    }

    auto body = nlohmann::json::parse(res->body);
    return body;
}

NetworkState Vault::OnlineDeleteFolder(std::string folderUUID) {
    httplib::Client client(vaultURL);

    httplib::Headers headers = {
        { "authorization", "Bearer " + authData["accessString"].get<std::string>() },
        { "Content-Type", "application/json" },
        { "bitwarden-client-name", "web" },
        { "bitwarden-client-version", "2026.3.0" },
    };

    auto res = client.Delete("/api/folders/" + folderUUID, headers);

    if (!res) {
        spdlog::error("deleteFolder request failed");
        return NetworkState::Failed;
    }
    if (res->status != 200) {
        spdlog::error("deleteFolder failed: {}", res->status);
        return NetworkState::Failed;
    }
}

std::expected<std::vector<uint8_t>, NetworkState> Vault::OnlineDownloadIcon(std::string url) {
    httplib::Client client(iconURL);

    auto res = client.Get("/" + url + "/icon.png");

    if (!res) {
        spdlog::error("downloadIcon request failed");
        return std::unexpected(NetworkState::Failed);
    }
    if (res->status != 200) {
        spdlog::error("downloadIcon failed: {}", res->status);
        return std::unexpected(NetworkState::Failed);
    }

    return std::vector<uint8_t>(res->body.begin(), res->body.end());
}