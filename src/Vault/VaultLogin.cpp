#include "Vault.h"

bool Vault::login(std::string& password) {
    if (!storage.exists("data.json") || 
        !jsonData.contains("expiresIn") || 
        !jsonData.contains("refreshToken") || 
        !jsonData.contains("accessString") || 
        !jsonData.contains("email")) {
        spdlog::info("ds");
        return false;
    }

    if (jsonData["expiresIn"].get<int>() == 0 || 
        jsonData["refreshToken"].get<std::string>() == "" || 
        jsonData["accessString"].get<std::string>() == "" || 
        jsonData["email"].get<std::string>() == "") {
        spdlog::info("dd");
        return false;
    }

    if (!storage.exists("vault.json")) {
        sync();
    }

    unlock(password);

    if (needsRefresh()) {
        refreshToken();
    }

    if (shouldRefresh == false) {
        shouldRefresh = true;

        if (refreshThread.joinable()) {
            refreshThread.join();
        }

        refreshThread = std::thread(&Vault::refreshLoop, this);
    }

    return true;
}

std::string toHex(const std::vector<uint8_t>& data) {
    std::ostringstream oss;
    for (uint8_t byte : data)
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    return oss.str();
}

Errors Vault::FirstTimeLogin(std::string& password, std::string& email) {
    boost::algorithm::to_lower(email);
    preLogin(email);

    jsonData["email"] = email;

    internalKey = makeKey(password, jsonData["salt"], jsonData["kdfIterations"]);
    masterPasswordHash = hashedPassword(password, jsonData["salt"], jsonData["kdfIterations"]);

    /*
     * Erase the password safely
    */
    OPENSSL_cleanse(password.data(), password.size());
    password.clear();

    return getToken("", Type::None);
}

void Vault::FirstTimeLoginOTP(std::string otp) {
    getToken(otp, Type::OTP);
}

void Vault::FirstTimeLoginDeviceVerify(std::string code) {
    getToken(code, Type::NewDevice);
}

void Vault::unlock(std::string& password) {
    internalKey = makeKey(password, jsonData["salt"], jsonData["kdfIterations"]);
    masterPasswordHash = hashedPassword(password, jsonData["salt"], jsonData["kdfIterations"]);

    /*
     * Erase the password safely
    */
    OPENSSL_cleanse(password.data(), password.size());
    password.clear();

    std::string protectedKey = vaultData["profile"]["key"];

    std::vector<uint8_t> decryptedProtectedKey = InternalDecrypt(protectedKey, internalKey, internalKey);

    encKey = std::vector<uint8_t>(decryptedProtectedKey.begin(), decryptedProtectedKey.begin() + 32);
    macKey = std::vector<uint8_t>(decryptedProtectedKey.begin() + 32, decryptedProtectedKey.end());

    OPENSSL_cleanse(decryptedProtectedKey.data(), decryptedProtectedKey.size());
}

void Vault::sync() {
    httplib::Client client("https://vault.bitwarden.com");

    httplib::Headers headers = {
        { "authorization", "Bearer " + jsonData["accessString"].get<std::string>() },
        { "Accept", "application/json" },
        { "bitwarden-client-name", "web" },
        { "bitwarden-client-version", "2026.3.0" },
    };

    auto res = client.Get("/api/sync", headers);

    if (!res) {
        spdlog::error("sync request failed");
        throw std::runtime_error("sync request failed");
    }
    if (res->status != 200) {
        spdlog::error("sync failed: {}", res->status);
        throw std::runtime_error("sync failed: " + std::to_string(res->status));
    }

    auto body = nlohmann::json::parse(res->body);

    if (!storage.exists("vault.json")) {
        storage.write("vault.json", body.dump(4));
        vaultData = body;
        std::string protectedKey = vaultData["profile"]["key"];

        std::vector<uint8_t> decryptedProtectedKey = InternalDecrypt(protectedKey, internalKey, internalKey);

        encKey = std::vector<uint8_t>(decryptedProtectedKey.begin(), decryptedProtectedKey.begin() + 32);
        macKey = std::vector<uint8_t>(decryptedProtectedKey.begin() + 32, decryptedProtectedKey.end());

        OPENSSL_cleanse(decryptedProtectedKey.data(), decryptedProtectedKey.size());

        spdlog::info("encKey: {}, macKey: {}", toHex(encKey), toHex(macKey));
        return;
    }

    std::string Vault = storage.read("vault.json");
    vaultData = nlohmann::json::parse(Vault);

    //       ID           Revision
    std::map<std::string, std::string> currentRevisions;

    for (const auto& cipher : vaultData["ciphers"]) {
        if (!cipher.contains("id") || !cipher.contains("revisionDate")) {
            continue;
        }
        currentRevisions[cipher["id"]] = cipher["revisionDate"];
    }

    std::map<std::string, std::string> onlineRevisions;

    for (const auto& cipher : body["ciphers"]) {
        if (!cipher.contains("id") || !cipher.contains("revisionDate")) {
            continue;
        }
        onlineRevisions[cipher["id"]] = cipher["revisionDate"];
    }

    for (const auto& [id, rev] : onlineRevisions) {
        auto it = currentRevisions.find(id);

        if (it == currentRevisions.end()) {
            /*
             * Since the item exists online,
             * but not locally, we need to add
             * it locally.
            */
            for (const auto& cipher : body["ciphers"]) {
                if (!cipher.contains("id")) {
                    continue;
                }
                if (cipher["id"] == id) {
                    vaultData["ciphers"].push_back(cipher);
                    break;
                }
            }
        } else {
            const std::string& localRev = it->second;
            const std::string& localId = it->first;

            std::time_t localTime = BitwardenTime(localRev);
            std::time_t onlineTime = BitwardenTime(rev);
            
            if (onlineTime > localTime) {
                /*
                 * Since the Online Version is Newer, 
                 * we need to update the local one.
                */
                for (const auto& cipher : body["ciphers"]) {
                    if (!cipher.contains("id")) {
                        continue;
                    }
                    if (cipher["id"] != id) {
                        continue;
                    }
                    for (auto& cipherLocal : vaultData["ciphers"]) {
                        if (!cipherLocal.contains("id")) {
                            continue;
                        }

                        if (cipherLocal["id"] == id) {
                            cipherLocal = cipher;
                            break;
                        }
                    }
                    break;
                }
            } else if (onlineTime < localTime) {
                for (const auto& cipher : vaultData["ciphers"]) {
                    if (!cipher.contains("id")) {
                        continue;
                    }
                    if (cipher["id"] == localId) {
                        updateItem(cipher);
                        break;
                    }
                }
            }
        }
    }

    storage.write("vault.json", vaultData.dump(4));
}