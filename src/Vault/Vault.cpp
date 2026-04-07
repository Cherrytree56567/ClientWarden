#include "Vault.h"

Vault::Vault() {
    spdlog::set_pattern("[%H:%M:%S] [ClientWarden::Vault] [%^---%L---%$] [thread %t] %v");

    if (storage.exists("data.json")) {
        try {
            jsonData = nlohmann::json::parse(storage.read("data.json"));
        } catch (const nlohmann::json::parse_error& e) {
            spdlog::error("JSON parse error: {}", e.what());
            storage.rename("data.json", "corrupt.data.json");
        }
    }
}

Vault::~Vault() {
    shouldRefresh = false;

    if (refreshThread.joinable()) {
        refreshThread.join();
    }
}

void Vault::preLogin(const std::string& email) {
    httplib::Client client("https://vault.bitwarden.com");

    httplib::Headers headers = {
        { "Content-Type", "application/json" },
        { "bitwarden-client-name", "web" },
        { "bitwarden-client-version", "2026.3.0" },
    };

    auto res = client.Post("/identity/accounts/prelogin", headers, "{\"email\":\"" + email + "\"}", "application/json");

    if (!res) {
        spdlog::error("prelogin request failed");
        throw std::runtime_error("prelogin request failed");
    }
    if (res->status != 200) {
        spdlog::error("prelogin failed: {}", res->status);
        throw std::runtime_error("prelogin failed: " + std::to_string(res->status));
    }

    auto body = nlohmann::json::parse(res->body);
    jsonData["kdfIterations"] = body["kdfIterations"];
    jsonData["salt"] = body["salt"];
}

Errors Vault::getToken(std::string code, Type type) {
    boost::uuids::uuid guid = boost::uuids::random_generator()(); 
    std::string uniqueDeviceGuid = boost::lexical_cast<std::string>(guid);

    httplib::Client client("https://vault.bitwarden.com");

    client.set_default_headers({
        { "Accept", "application/json" },
        { "Content-Type", "application/x-www-form-urlencoded; charset=utf-8" },
        { "bitwarden-client-name", "web" },
        { "bitwarden-client-version", "2026.3.0" },
    });

    httplib::Params data;
    data.emplace("grant_type", "password");
    data.emplace("username", jsonData["email"]);
    data.emplace("password", masterPasswordHash);
    data.emplace("scope", "api offline_access");
    data.emplace("client_id", "web");
    data.emplace("deviceType", "10");
    data.emplace("deviceIdentifier", uniqueDeviceGuid);
    data.emplace("deviceName", "firefox");

    if (type == Type::OTP) {
        data.emplace("twoFactorToken", code);
        data.emplace("twoFactorProvider", "0");
        data.emplace("twoFactorRemember", "0");
    } else if (type == Type::NewDevice) {
        data.emplace("newDeviceOtp", code);
    }
    
    auto res = client.Post("/identity/connect/token", data);

    if (res->status == 400) {
        auto body = nlohmann::json::parse(res->body);
        if (body["error_description"] == "Two factor required.") {
            return Errors::NeedsOTP;
        } else if (body["error_description"] == "New device verification required") {
            return Errors::NeedsNewDevice;
        }
    }

    if (!res) {
        spdlog::error("getToken request failed");
        throw std::runtime_error("getToken request failed");
    }
    if (res->status != 200) {
        spdlog::error("getToken failed: {}", res->status);
        throw std::runtime_error("getToken failed: " + std::to_string(res->status));
    }

    auto body = nlohmann::json::parse(res->body);
    jsonData["accessString"] = body["access_token"];
    jsonData["refreshToken"] = body["refresh_token"];
    jsonData["expiresIn"] = body["expires_in"];

    std::time_t now = std::time(nullptr) + jsonData["expiresIn"].get<int>();
    std::tm* localTime = std::localtime(&now);

    std::ostringstream oss;
    oss << std::put_time(localTime, "%Y-%m-%d %H:%M:%S");
    jsonData["needsRefreshTime"] = oss.str();

    storage.write("data.json", jsonData.dump(4));

    return Errors::Success;
}