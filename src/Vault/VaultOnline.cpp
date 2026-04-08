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
        spdlog::error("preLogin failed: {}", res->status);
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