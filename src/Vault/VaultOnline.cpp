#include "Vault.h"

namespace ClientWarden::Vault {
    NetworkState Vault::preLogin(std::string& email) {
        httplib::Client client(authData["vaultURL"]);

        httplib::Headers headers = {
            { "Content-Type", "application/json" },
            { "bitwarden-client-name", "web" },
            { "bitwarden-client-version", "2026.3.0" },
        };

        auto res = client.Post("/identity/accounts/prelogin", headers, "{\"email\":\"" + email + "\"}", "application/json");

        if (!res) {
            logger->error("preLogin request failed");
            return NetworkState::Failed;
        }
        if (res->status != 200) {
            logger->error("preLogin failed: {}, {}", res->status, res->body);
            return NetworkState::Failed;
        }

        auto body = nlohmann::json::parse(res->body);
        authData["kdfIterations"] = body["kdfIterations"];
        authData["salt"] = email;
        authData["email"] = email;

        return NetworkState::Success;
    }

    AuthState Vault::getToken() {
        httplib::Client client(authData["vaultURL"]);

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
                logger->warn("Needs Two Factor Auth.");
                return AuthState::NeedsTOTP;
            } else if (body["error_description"] == "New device verification required") {
                logger->warn("Needs New Device Verification.");
                return AuthState::NeedsEmailVerification;
            }
        }

        if (!res) {
            logger->error("getToken request failed");
            return AuthState::Failed;
        }
        if (res->status != 200) {
            logger->error("getToken failed: {}", res->status);
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
        httplib::Client client(authData["vaultURL"]);

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
            logger->error("getToken request failed");
            return AuthState::Failed;
        }
        if (res->status != 200) {
            logger->error("getToken failed: {}", res->status);
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
        httplib::Client client(authData["vaultURL"]);

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
            logger->error("getToken request failed");
            return AuthState::Failed;
        }
        if (res->status != 200) {
            logger->error("getToken failed: {}", res->status);
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
        httplib::Client client(authData["apiURL"]);
        client.set_connection_timeout(1);
        auto res = client.Get("/alive");
        return res && res->status == 200;
    }

    bool Vault::checkAccessTokenValidity() {
        httplib::Client client(authData["apiURL"]);
        client.set_connection_timeout(3);
        
        httplib::Headers headers = {
            {"Authorization", "Bearer " + authData["accessString"].get<std::string>()}
        };
        
        auto res = client.Get("/api/accounts/profile", headers);
        return res && res->status != 401;
    }

    std::expected<nlohmann::json, NetworkState> Vault::OnlineNewItem(nlohmann::json encryptedData) {
        httplib::Client client(authData["vaultURL"]);

        httplib::Headers headers = {
            { "authorization", "Bearer " + authData["accessString"].get<std::string>() },
            { "Content-Type", "application/json" },
            { "bitwarden-client-name", "web" },
            { "bitwarden-client-version", "2026.3.0" },
        };

        auto res = client.Post("/api/ciphers", headers, encryptedData.dump(), "application/json");

        if (!res) {
            logger->error("newItem request failed");
            return std::unexpected(NetworkState::Failed);
        }
        if (res->status != 200) {
            logger->error("newItem failed: {}", res->status);
            return std::unexpected(NetworkState::Failed);
        }

        auto body = nlohmann::json::parse(res->body);
        return body;
    }

    std::expected<nlohmann::json, NetworkState> Vault::OnlineUpdateItem(nlohmann::json encryptedData) {
        if (!encryptedData.contains("id")) {
            return nlohmann::json();
        }
        httplib::Client client(authData["vaultURL"]);

        httplib::Headers headers = {
            { "authorization", "Bearer " + authData["accessString"].get<std::string>() },
            { "Content-Type", "application/json" },
            { "bitwarden-client-name", "web" },
            { "bitwarden-client-version", "2026.3.0" },
        };

        auto res = client.Put("/api/ciphers/" + encryptedData["id"].get<std::string>(), headers, encryptedData.dump(), "application/json");

        if (!res) {
            logger->error("updateItem request failed");
            return std::unexpected(NetworkState::Failed);
        }
        if (res->status != 200) {
            logger->error("updateItem failed: {}", res->status);
            return std::unexpected(NetworkState::Failed);
        }

        auto body = nlohmann::json::parse(res->body);
        return body;
    }

    NetworkState Vault::OnlineDeleteItem(std::string uuid) {
        httplib::Client client(authData["vaultURL"]);

        httplib::Headers headers = {
            { "authorization", "Bearer " + authData["accessString"].get<std::string>() },
            { "Content-Type", "application/json" },
            { "bitwarden-client-name", "web" },
            { "bitwarden-client-version", "2026.3.0" },
        };

        auto res = client.Delete("/api/ciphers/" + uuid, headers);

        if (!res) {
            logger->error("deleteItem request failed");
            return NetworkState::Failed;
        }
        if (res->status != 200) {
            logger->error("deleteItem failed: {}", res->status);
            return NetworkState::Failed;
        }
        return NetworkState::Success;
    }

    NetworkState Vault::OnlineSoftDeleteItem(std::string uuid) {
        httplib::Client client(authData["vaultURL"]);
        httplib::Headers headers = {
            { "authorization", "Bearer " + authData["accessString"].get<std::string>() },
            { "Content-Type", "application/json" },
            { "bitwarden-client-name", "web" },
            { "bitwarden-client-version", "2026.3.0" },
        };
        auto res = client.Put("/api/ciphers/" + uuid + "/delete", headers, "", "application/json");
        if (!res) {
            logger->error("softDeleteItem request failed");
            return NetworkState::Failed;
        }
        if (res->status != 200) {
            logger->error("softDeleteItem failed: {}", res->status);
            return NetworkState::Failed;
        }
        return NetworkState::Success;
    }

    NetworkState Vault::OnlineRestoreItem(std::string uuid) {
        httplib::Client client(authData["vaultURL"]);
        httplib::Headers headers = {
            { "authorization", "Bearer " + authData["accessString"].get<std::string>() },
            { "Content-Type", "application/json" },
            { "bitwarden-client-name", "web" },
            { "bitwarden-client-version", "2026.3.0" },
        };
        auto res = client.Put("/api/ciphers/" + uuid + "/restore", headers, "", "application/json");
        if (!res) {
            logger->error("restoreItem request failed");
            return NetworkState::Failed;
        }
        if (res->status != 200) {
            logger->error("restoreItem failed: {}", res->status);
            return NetworkState::Failed;
        }
        return NetworkState::Success;
    }

    /*
     * TODO: Clear Secure Data
    */
    std::expected<std::string, NetworkState> Vault::OnlineAddAttachment(std::string uuid, std::string& decryptedFileContents, std::string& decryptedFileName, std::function<void(float)> onProgress) {
        httplib::Client client(authData["vaultURL"]);
        httplib::Headers headers = {
            { "authorization", "Bearer " + authData["accessString"].get<std::string>() },
            { "bitwarden-client-name", "web" },
            { "bitwarden-client-version", "2026.3.0" },
        };

        /*
         * SECRET DATA
        */
        auto [attEncKey, attMacKey] = generateEncMacKeys();

        std::vector<uint8_t> attKey(attEncKey.begin(), attEncKey.end());
        attKey.insert(attKey.end(), attMacKey.begin(), attMacKey.end());

        std::vector<uint8_t> cipEncKey = encKey;
        std::vector<uint8_t> cipMacKey = macKey;

        for (auto& cipher : vaultData["ciphers"]) {
            if (cipher.contains("id") && cipher["id"] == uuid) {
                if (!cipher["key"].is_null()) {
                    auto [cipEnc, cipMac] = getKeysFromCipher(cipher["key"]);
                    cipEncKey = cipEnc;
                    cipMacKey = cipMac;
                    OPENSSL_cleanse(cipEnc.data(), cipEnc.size());
                    OPENSSL_cleanse(cipMac.data(), cipMac.size());
                }
                break;
            }
        }
        
        std::string attKeyStr = InternalEncrypt(attKey, cipEncKey, cipMacKey);

        std::vector<uint8_t> encryptedFCvu8(decryptedFileContents.begin(), decryptedFileContents.end());

        std::string encryptedFileContents = InternalEncryptRaw(encryptedFCvu8, attEncKey, attMacKey);
        std::string encryptedFileName = Encrypt(decryptedFileName, cipEncKey, cipMacKey);

        OPENSSL_cleanse(attKey.data(), attKey.size());
        OPENSSL_cleanse(attEncKey.data(), attEncKey.size());
        OPENSSL_cleanse(attMacKey.data(), attMacKey.size());
        OPENSSL_cleanse(cipEncKey.data(), cipEncKey.size());
        OPENSSL_cleanse(cipMacKey.data(), cipMacKey.size());
        OPENSSL_cleanse(encryptedFCvu8.data(), encryptedFCvu8.size());
        OPENSSL_cleanse(decryptedFileContents.data(), decryptedFileContents.size());
        decryptedFileContents.clear();
        OPENSSL_cleanse(decryptedFileName.data(), decryptedFileName.size());
        decryptedFileName.clear();

        nlohmann::json requestData;
        requestData["adminRequest"] = false;
        requestData["fileName"] = encryptedFileName;
        requestData["fileSize"] = encryptedFileContents.size();
        requestData["key"] = attKeyStr;
        requestData["lastKnownRevisionDate"] = getBitwardenTime();

        auto res = client.Post("/api/ciphers/" + uuid + "/attachment/v2", headers, requestData.dump(), "application/json");
        if (!res) {
            logger->error("prepareAttachment request failed");
            return std::unexpected(NetworkState::Failed);
        }
        if (res->status != 200) {
            logger->error("prepareAttachment failed: {}", res->status);
            return std::unexpected(NetworkState::Failed);
        }

        auto body = nlohmann::json::parse(res->body);

        if (body.contains("cipherResponse")) {
            if (body["cipherResponse"].contains("attachments")) {
                auto attField = body["cipherResponse"]["attachments"];

                if (vaultData.contains("ciphers") && vaultData["ciphers"].is_array()) {
                    for (auto& cipher : vaultData["ciphers"]) {
                        if (cipher.contains("id") && cipher["id"] == uuid) {
                            cipher["attachments"] = attField;
                            break;
                        }
                    }
                }
            }
        }

        if (!body.contains("attachmentId")) return std::unexpected(NetworkState::Failed);
        if (!body["attachmentId"].is_string()) return std::unexpected(NetworkState::Failed);

        httplib::UploadFormDataItems items = {
            {
                "data",
                encryptedFileContents,
                encryptedFileName,
                "application/octet-stream"
            }
        };

        auto multres = client.Post("/api/ciphers/" + uuid + "/attachment/" + body["attachmentId"].get<std::string>(), headers, items, 
            [&onProgress](uint64_t current, uint64_t total) -> bool {
                if (onProgress && total > 0) {
                    onProgress(static_cast<float>(current) / static_cast<float>(total));
                }
                return true;
            });

        if (!multres) {
            logger->error("uploadAttachment request failed");
            return std::unexpected(NetworkState::Failed);
        }
        if (multres->status != 200) {
            logger->error("uploadAttachment failed: {}", multres->status);
            return std::unexpected(NetworkState::Failed);
        }

        return body["attachmentId"];
    }

    NetworkState Vault::OnlineRemoveAttachment(std::string uuid, std::string attachmentID) {
        httplib::Client client(authData["vaultURL"]);

        httplib::Headers headers = {
            { "authorization", "Bearer " + authData["accessString"].get<std::string>() },
            { "Content-Type", "application/json" },
            { "bitwarden-client-name", "web" },
            { "bitwarden-client-version", "2026.3.0" },
        };

        auto res = client.Delete("/api/ciphers/" + uuid + "/attachment/" + attachmentID, headers);

        if (!res) {
            logger->error("removeAttachment request failed");
            return NetworkState::Failed;
        }
        if (res->status != 200) {
            logger->error("removeAttachment failed: {}", res->status);
            return NetworkState::Failed;
        }
        return NetworkState::Success;
    }

    std::expected<std::string, NetworkState> Vault::OnlineDownloadAttachment(std::string uuid, std::string attachmentID, std::function<void(float)> onProgress) {
        httplib::Client client(authData["vaultURL"]);

        httplib::Headers headers = {
            { "authorization", "Bearer " + authData["accessString"].get<std::string>() },
            { "Content-Type", "application/json" },
            { "bitwarden-client-name", "web" },
            { "bitwarden-client-version", "2026.3.0" },
        };

        auto res = client.Get("/api/ciphers/" + uuid + "/attachment/" + attachmentID, headers);

        if (!res) {
            logger->error("downloadAttachment request failed");
            return std::unexpected(NetworkState::Failed);
        }
        if (res->status != 200) {
            logger->error("downloadAttachment failed: {}", res->status);
            return std::unexpected(NetworkState::Failed);
        }

        auto body = nlohmann::json::parse(res->body);

        if (!body.contains("url") || !body["url"].is_string()) return std::unexpected(NetworkState::Failed);
        if (!body.contains("fileName") || !body["fileName"].is_string()) return std::unexpected(NetworkState::Failed);
        if (!body.contains("key") || !body["key"].is_string()) return std::unexpected(NetworkState::Failed);

        std::vector<uint8_t> cipEncKey = encKey;
        std::vector<uint8_t> cipMacKey = macKey;

        for (auto& cipher : vaultData["ciphers"]) {
            if (cipher.contains("id") && cipher["id"] == uuid) {
                if (!cipher["key"].is_null()) {
                    auto [cipEnc, cipMac] = getKeysFromCipher(cipher["key"]);
                    cipEncKey = cipEnc;
                    cipMacKey = cipMac;
                    OPENSSL_cleanse(cipEnc.data(), cipEnc.size());
                    OPENSSL_cleanse(cipMac.data(), cipMac.size());
                }
                break;
            }
        }

        std::string attKeyPlain = Decrypt(body["key"], cipEncKey, cipMacKey);
        if (attKeyPlain.size() != 64) {
            logger->error("Attachment key wrong size: {}", attKeyPlain.size());
            return std::unexpected(NetworkState::Failed);
        }
        std::vector<uint8_t> decEnc(attKeyPlain.begin(), attKeyPlain.begin() + 32);
        std::vector<uint8_t> decMac(attKeyPlain.begin() + 32, attKeyPlain.end());
        OPENSSL_cleanse(attKeyPlain.data(), attKeyPlain.size());

        auto dlres = client.Get(body["url"], headers,
            [&onProgress](uint64_t current, uint64_t total) -> bool {
                if (onProgress && total > 0) {
                    onProgress(static_cast<float>(current) / static_cast<float>(total));
                }
                return true;
            });

        if (!dlres) {
            logger->error("downloadAttachment request failed");
            return std::unexpected(NetworkState::Failed);
        }
        if (dlres->status != 200) {
            logger->error("downloadAttachment failed: {}", dlres->status);
            return std::unexpected(NetworkState::Failed);
        }

        const std::string& buf = dlres->body;
        if (buf.size() < 1 + 16 + 32 + 1) {
            logger->error("Blob too short after decode: {}", buf.size());
            return std::unexpected(NetworkState::Failed);
        }
        if (buf[0] != 0x02) {
            logger->error("Unexpected enc type: 0x{:02x}", buf[0]);
            return std::unexpected(NetworkState::Failed);
        }

        std::vector<uint8_t> vecBuf(buf.begin(), buf.end());

        std::string decBody = InternalDecryptRaw(vecBuf, decEnc, decMac);

        vecBuf.clear();
        OPENSSL_cleanse(decEnc.data(), decEnc.size());
        OPENSSL_cleanse(decMac.data(), decMac.size());

        return std::move(decBody);
    }

    std::expected<nlohmann::json, NetworkState> Vault::OnlineCreateFolder(std::string encryptedFolderName) {
        httplib::Client client(authData["vaultURL"]);

        httplib::Headers headers = {
            { "authorization", "Bearer " + authData["accessString"].get<std::string>() },
            { "Content-Type", "application/json" },
            { "bitwarden-client-name", "web" },
            { "bitwarden-client-version", "2026.3.0" },
        };

        auto res = client.Post("/api/folders", headers, "{\"name\": \"" + encryptedFolderName + "\"}", "application/json");

        if (!res) {
            logger->error("createFolder request failed");
            return std::unexpected(NetworkState::Failed);
        }
        if (res->status != 200) {
            logger->error("createFolder failed: {}", res->status);
            return std::unexpected(NetworkState::Failed);
        }

        auto body = nlohmann::json::parse(res->body);
        return body;
    }

    std::expected<nlohmann::json, NetworkState> Vault::OnlineRenameFolder(std::string folderUUID, std::string encryptedFolderName) {
        httplib::Client client(authData["vaultURL"]);

        httplib::Headers headers = {
            { "authorization", "Bearer " + authData["accessString"].get<std::string>() },
            { "Content-Type", "application/json" },
            { "bitwarden-client-name", "web" },
            { "bitwarden-client-version", "2026.3.0" },
        };

        auto res = client.Put("/api/folders/" + folderUUID, headers, "{\"name\": \"" + encryptedFolderName + "\"}", "application/json");

        if (!res) {
            logger->error("renameFolder request failed");
            return std::unexpected(NetworkState::Failed);
        }
        if (res->status != 200) {
            logger->error("renameFolder failed: {}", res->status);
            return std::unexpected(NetworkState::Failed);
        }

        auto body = nlohmann::json::parse(res->body);
        return body;
    }

    NetworkState Vault::OnlineDeleteFolder(std::string folderUUID) {
        httplib::Client client(authData["vaultURL"]);

        httplib::Headers headers = {
            { "authorization", "Bearer " + authData["accessString"].get<std::string>() },
            { "Content-Type", "application/json" },
            { "bitwarden-client-name", "web" },
            { "bitwarden-client-version", "2026.3.0" },
        };

        auto res = client.Delete("/api/folders/" + folderUUID, headers);

        if (!res) {
            logger->error("deleteFolder request failed");
            return NetworkState::Failed;
        }
        if (res->status != 200) {
            logger->error("deleteFolder failed: {}", res->status);
            return NetworkState::Failed;
        }
        return NetworkState::Success;
    }

    std::expected<std::vector<uint8_t>, NetworkState> Vault::OnlineDownloadIcon(std::string url) {
        httplib::Client client(authData["iconURL"]);

        if (url.starts_with("https://")) {
            url = url.substr(8);
        } else if (url.starts_with("http://")) {
            url = url.substr(7);
        }

        auto res = client.Get("/" + url + "/icon.png");

        if (!res) {
            logger->error("downloadIcon request failed");
            return std::unexpected(NetworkState::Failed);
        }
        if (res->status != 200) {
            logger->error("downloadIcon failed: {}", res->status);
            return std::unexpected(NetworkState::Failed);
        }

        return std::vector<uint8_t>(res->body.begin(), res->body.end());
    }
}