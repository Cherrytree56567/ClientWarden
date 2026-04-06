#include "Vault.h"

bool Vault::needsRefresh() {
    std::tm tm = {};
    std::istringstream ss(jsonData["needsRefreshTime"].get<std::string>());
    ss >> std::get_time(&tm, "%Y-%m-%d %H:%M:%S");
    tm.tm_isdst = -1;
    std::time_t expiry = std::mktime(&tm);
    std::time_t now = std::time(nullptr);


    if (now >= expiry) {
        return true;
    }
    return false;
}

void Vault::refreshToken() {
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
    data.emplace("grant_type", "refresh_token");
    data.emplace("client_id", "web");
    data.emplace("refresh_token", jsonData["refreshToken"].get<std::string>());
    
    auto res = client.Post("/identity/connect/token", data);

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
    jsonData["expiresIn"] = body["expires_in"];

    std::time_t now = std::time(nullptr) + jsonData["expiresIn"].get<int>();
    std::tm* localTime = std::localtime(&now);

    std::ostringstream oss;
    oss << std::put_time(localTime, "%Y-%m-%d %H:%M:%S");
    jsonData["needsRefreshTime"] = oss.str();

    storage.write("data.json", jsonData.dump(4));
}

void Vault::refreshLoop() {
    while (shouldRefresh) {
        spdlog::info("Checking Refresh");
        if (needsRefresh()) {
            refreshToken();
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}