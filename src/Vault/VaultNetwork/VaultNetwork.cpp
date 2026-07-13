#include "VaultNetwork.h"

namespace ClientWarden {
    VaultNetwork::VaultNetwork() {

    }

    VaultNetwork::~VaultNetwork() {

    }

    void VaultNetwork::initNetwork(std::string vaultUri, std::string mainUri, std::string apiUri, std::string iconUri) {
        apiClient = std::make_shared<httplib::Client>(apiUri);
        vaultClient = std::make_shared<httplib::Client>(vaultUri);
        iconClient = std::make_shared<httplib::Client>(iconUri);
        iconClient->set_connection_timeout(2);
        iconClient->set_read_timeout(3);
    }

    std::optional<nlohmann::json> VaultNetwork::preLogin(std::string& email) {
        httplib::Headers headers = {
            { "Content-Type", "application/json" },
            { "bitwarden-client-name", "web" },
            { "bitwarden-client-version", "2026.3.0" },
        };

        auto res = vaultClient->Post("/identity/accounts/prelogin", headers, "{\"email\":\"" + email + "\"}", "application/json");

        if (!res) {
            logger->error("preLogin request failed");
            return std::nullopt;
        }
        if (res->status != 200) {
            logger->error("preLogin failed: {}, {}", res->status, res->body);
            return std::nullopt;
        }

        return nlohmann::json::parse(res->body);
    }

    std::optional<nlohmann::json> VaultNetwork::getToken(std::string& email, std::string& masterPasswordHash) {
        vaultClient->set_default_headers({
            { "Accept", "application/json" },
            { "Content-Type", "application/x-www-form-urlencoded; charset=utf-8" },
            { "bitwarden-client-name", "web" },
            { "bitwarden-client-version", "2026.3.0" },
        });

        httplib::Params data;
        data.emplace("grant_type", "password");
        data.emplace("username", email);
        data.emplace("password", masterPasswordHash);
        data.emplace("scope", "api offline_access");
        data.emplace("client_id", "web");
        data.emplace("deviceType", "10");
        data.emplace("deviceIdentifier", uniqueGuid());
        data.emplace("deviceName", "firefox");
        
        auto res = vaultClient->Post("/identity/connect/token", data);

        if (!res) {
            logger->error("getToken request failed");
            return std::nullopt;
        }
        if (res->status == 400) {
            return nlohmann::json::parse(res->body);
        }
        if (res->status != 200) {
            logger->error("getToken failed: {}", res->status);
            return std::nullopt;
        }

        return nlohmann::json::parse(res->body);
    }

    std::optional<nlohmann::json> VaultNetwork::getTokenWTotp(std::string& email, std::string& masterPasswordHash, std::string& totp) {
        vaultClient->set_default_headers({
            { "Accept", "application/json" },
            { "Content-Type", "application/x-www-form-urlencoded; charset=utf-8" },
            { "bitwarden-client-name", "web" },
            { "bitwarden-client-version", "2026.3.0" },
        });

        httplib::Params data;
        data.emplace("grant_type", "password");
        data.emplace("username", email);
        data.emplace("password", masterPasswordHash);
        data.emplace("scope", "api offline_access");
        data.emplace("client_id", "web");
        data.emplace("deviceType", "10");
        data.emplace("deviceIdentifier", uniqueGuid());
        data.emplace("deviceName", "firefox");
        data.emplace("twoFactorToken", totp);
        data.emplace("twoFactorProvider", "0");
        data.emplace("twoFactorRemember", "0");
        
        auto res = vaultClient->Post("/identity/connect/token", data);

        if (!res) {
            logger->error("getToken request failed");
            return std::nullopt;
        }
        if (res->status != 200) {
            logger->error("getToken failed: {}", res->status);
            return std::nullopt;
        }

        return nlohmann::json::parse(res->body);
    }

    std::optional<nlohmann::json> VaultNetwork::getTokenWDeviceVerify(std::string& email, std::string& masterPasswordHash, std::string& code) {
        vaultClient->set_default_headers({
            { "Accept", "application/json" },
            { "Content-Type", "application/x-www-form-urlencoded; charset=utf-8" },
            { "bitwarden-client-name", "web" },
            { "bitwarden-client-version", "2026.3.0" },
        });

        httplib::Params data;
        data.emplace("grant_type", "password");
        data.emplace("username", email);
        data.emplace("password", masterPasswordHash);
        data.emplace("scope", "api offline_access");
        data.emplace("client_id", "web");
        data.emplace("deviceType", "10");
        data.emplace("deviceIdentifier", uniqueGuid());
        data.emplace("deviceName", "firefox");
        data.emplace("newDeviceOtp", code);
        
        auto res = vaultClient->Post("/identity/connect/token", data);

        if (!res) {
            logger->error("getToken request failed");
            return std::nullopt;
        }
        if (res->status != 200) {
            logger->error("getToken failed: {}", res->status);
            return std::nullopt;
        }

        return nlohmann::json::parse(res->body);
    }

    bool VaultNetwork::checkConnectivity() {
        apiClient->set_connection_timeout(1);

        auto res = apiClient->Get("/alive");

        bool alive = res && res->status == 200;

        if (alive) {
            connectivity = VaultConnectivity::Online;
        } else {
            connectivity = VaultConnectivity::Offline;
        }

        return alive;
    }

    bool VaultNetwork::checkAccessTokenValidity(std::string accessString) {
        apiClient->set_connection_timeout(3);
        
        httplib::Headers headers = {
            {"Authorization", "Bearer " + accessString}
        };
        
        auto res = apiClient->Get("/api/accounts/profile", headers);
        return res && res->status != 401;
    }

    std::optional<nlohmann::json> VaultNetwork::refreshToken(std::string refreshToken) {
        boost::uuids::uuid guid = boost::uuids::random_generator()(); 
        std::string uniqueDeviceGuid = boost::lexical_cast<std::string>(guid);
        vaultClient->set_default_headers({
            { "Accept", "application/json" },
            { "Content-Type", "application/x-www-form-urlencoded; charset=utf-8" },
            { "bitwarden-client-name", "web" },
            { "bitwarden-client-version", "2026.3.0" },
        });

        httplib::Params data;
        data.emplace("grant_type", "refresh_token");
        data.emplace("client_id", "web");
        data.emplace("refresh_token", refreshToken);
        
        auto res = vaultClient->Post("/identity/connect/token", data);

        if (!res) {
            logger->error("getToken request failed");
            return std::nullopt;
        }
        if (res->status != 200) {
            logger->error("getToken failed: {}", res->status);
            return std::nullopt;
        }

        return nlohmann::json::parse(res->body);
    }

    bool VaultNetwork::websocketLoop(std::function<void(int notifyType)> onNotification, std::string accessString, std::string wssURL,
        const std::atomic<bool>& shouldThread) {
        std::string wsUri = wssURL + "/notifications/hub";

        httplib::Headers headers = {
            { "Authorization", "Bearer " + accessString }
        };

        httplib::ws::WebSocketClient ws(wsUri, headers);
        
        if (!ws.connect()) {
            logger->error("Websocket failed");
            return false;
        }

        ws.send("{\"protocol\":\"messagepack\",\"version\":1}\x1e");

        std::string msg;

        while (ws.read(msg)) {
            if (!shouldThread) {
                ws.close();
                break;
            }

            if (msg == "{}\x1e") continue;

            size_t headerLen = 0;
            const auto* raw = reinterpret_cast<const uint8_t*>(msg.data());
            for (size_t i = 0; i < msg.size() && i < 5; i++) {
                headerLen++;
                if (!(raw[i] & 0x80)) break;
            }

            msgpack::object_handle oh = msgpack::unpack(
                msg.data() + headerLen,
                msg.size() - headerLen
            );
            msgpack::object obj = oh.get();

            auto& arr = obj.via.array;

            if (arr.size < 5) continue;
            int signalrType = arr.ptr[0].as<int>();
            if (signalrType != 1) continue;

            auto& args = arr.ptr[4].via.array;
            if (args.size < 1) continue;

            auto& notification = args.ptr[0].via.map;

            int notifyType = -1;
            std::string cipherId;

            for (uint32_t i = 0; i < notification.size; i++) {
                std::string key = notification.ptr[i].key.as<std::string>();

                if (key == "Type") {
                    notifyType = notification.ptr[i].val.as<int>();
                } else if (key == "Payload") {
                    auto& payload = notification.ptr[i].val.via.map;
                    for (uint32_t j = 0; j < payload.size; j++) {
                        std::string pkey = payload.ptr[j].key.as<std::string>();
                        if (pkey == "Id" && payload.ptr[j].val.type == msgpack::type::STR) {
                            cipherId = payload.ptr[j].val.as<std::string>();
                        }
                    }
                }
            }

            if (onNotification) {
                onNotification(notifyType);
            }
        }
        return true;
    }

    std::optional<nlohmann::json> VaultNetwork::getVault(std::string accessString) {
        httplib::Headers headers = {
            { "authorization", "Bearer " + accessString },
            { "Accept", "application/json" },
            { "bitwarden-client-name", "web" },
            { "bitwarden-client-version", "2026.3.0" },
        };

        auto res = vaultClient->Get("/api/sync", headers);

        if (!res) {
            logger->error("sync request failed");
            return std::nullopt;
        }
        if (res->status != 200) {
            logger->error("sync failed: {}", res->status);
            return std::nullopt;
        }

        return nlohmann::json::parse(res->body);
    }

    std::optional<nlohmann::json> VaultNetwork::NewItem(nlohmann::json encryptedData, std::string accessString) {
        httplib::Headers headers = {
            { "authorization", "Bearer " + accessString },
            { "Content-Type", "application/json" },
            { "bitwarden-client-name", "web" },
            { "bitwarden-client-version", "2026.3.0" },
        };

        auto res = vaultClient->Post("/api/ciphers", headers, encryptedData.dump(), "application/json");

        if (!res) {
            logger->error("newItem request failed");
            return std::nullopt;
        }
        if (res->status != 200) {
            logger->error("newItem failed: {}", res->status);
            return std::nullopt;
        }

        return nlohmann::json::parse(res->body);
    }

    std::optional<nlohmann::json> VaultNetwork::UpdateItem(nlohmann::json encryptedData, std::string accessString) {
        httplib::Headers headers = {
            { "authorization", "Bearer " + accessString },
            { "Content-Type", "application/json" },
            { "bitwarden-client-name", "web" },
            { "bitwarden-client-version", "2026.3.0" },
        };

        if (!encryptedData.contains("id")) {
            return std::nullopt;
        }

        std::string data = encryptedData.dump();

        auto res = vaultClient->Put("/api/ciphers/" + encryptedData["id"].get<std::string>(), headers, data, "application/json");

        if (!res) {
            logger->error("updateItem request failed");
            return std::nullopt;
        }
        if (res->status != 200) {
            logger->error("updateItem failed: {}", res->status);
            return std::nullopt;
        }

        return nlohmann::json::parse(res->body);
    }

    bool VaultNetwork::DeleteItem(std::string uuid, std::string accessString) {
        httplib::Headers headers = {
            { "authorization", "Bearer " + accessString },
            { "Content-Type", "application/json" },
            { "bitwarden-client-name", "web" },
            { "bitwarden-client-version", "2026.3.0" },
        };

        auto res = vaultClient->Delete("/api/ciphers/" + uuid, headers);

        if (!res) {
            logger->error("deleteItem request failed");
            return false;
        }
        if (res->status != 200) {
            logger->error("deleteItem failed: {}", res->status);
            return false;
        }

        return true;
    }

    bool VaultNetwork::SoftDeleteItem(std::string uuid, std::string accessString) {
        httplib::Headers headers = {
            { "authorization", "Bearer " + accessString },
            { "Content-Type", "application/json" },
            { "bitwarden-client-name", "web" },
            { "bitwarden-client-version", "2026.3.0" },
        };

        auto res = vaultClient->Put("/api/ciphers/" + uuid + "/delete", headers, "", "application/json");

        if (!res) {
            logger->error("softDeleteItem request failed");
            return false;
        }
        if (res->status != 200) {
            logger->error("softDeleteItem failed: {}", res->status);
            return false;
        }

        return true;
    }

    bool VaultNetwork::RestoreItem(std::string uuid, std::string accessString) {
        httplib::Headers headers = {
            { "authorization", "Bearer " + accessString },
            { "Content-Type", "application/json" },
            { "bitwarden-client-name", "web" },
            { "bitwarden-client-version", "2026.3.0" },
        };

        auto res = vaultClient->Put("/api/ciphers/" + uuid + "/restore", headers, "", "application/json");

        if (!res) {
            logger->error("restoreItem request failed");
            return false;
        }
        if (res->status != 200) {
            logger->error("restoreItem failed: {}", res->status);
            return false;
        }
        
        return true;
    }

    std::optional<nlohmann::json> VaultNetwork::AddAttachment(std::string uuid, std::string& encryptedFileContents, 
        std::string& encryptedFileName, std::string& attKeyStr, std::string accessString, std::function<void(float)> onProgress) {
        httplib::Headers headers = {
            { "authorization", "Bearer " + accessString },
            { "bitwarden-client-name", "web" },
            { "bitwarden-client-version", "2026.3.0" },
        };

        nlohmann::json requestData;
        requestData["adminRequest"] = false;
        requestData["fileName"] = encryptedFileName;
        requestData["fileSize"] = encryptedFileContents.size();
        requestData["key"] = attKeyStr;
        requestData["lastKnownRevisionDate"] = getBitwardenTime();

        auto res = vaultClient->Post("/api/ciphers/" + uuid + "/attachment/v2", headers, requestData.dump(), "application/json");
        if (!res) {
            logger->error("prepareAttachment request failed");
            return std::nullopt;
        }
        if (res->status != 200) {
            logger->error("prepareAttachment failed: {}", res->status);
            return std::nullopt;
        }

        nlohmann::json body = nlohmann::json::parse(res->body);

        std::string attachmentBody = body["cipherResponse"]["attachments"];

        if (!body.contains("cipherResponse")) {
            return std::nullopt;
        }
        if (!body["cipherResponse"].contains("attachments")) {
            return std::nullopt;
        }

        if (!body.contains("attachmentId")) {
            return std::nullopt;
        }
        if (!body["attachmentId"].is_string()) {
            return std::nullopt;
        }

        httplib::UploadFormDataItems items = {
            {
                "data",
                encryptedFileContents,
                encryptedFileName,
                "application/octet-stream"
            }
        };

        auto uploadRes = vaultClient->Post("/api/ciphers/" + uuid + "/attachment/" + body["attachmentId"].get<std::string>(), headers, items, 
            [&onProgress](uint64_t current, uint64_t total) -> bool {
                if (onProgress && total > 0) {
                    onProgress(static_cast<float>(current) / static_cast<float>(total));
                }
                return true;
            });

        if (!uploadRes) {
            logger->error("uploadAttachment request failed");
            return std::nullopt;
        }
        if (uploadRes->status != 200) {
            logger->error("uploadAttachment failed: {}", uploadRes->status);
            return std::nullopt;
        }

        return body;
    }

    bool VaultNetwork::RemoveAttachment(std::string uuid, std::string attachmentID, std::string accessString) {
        httplib::Headers headers = {
            { "authorization", "Bearer " + accessString },
            { "Content-Type", "application/json" },
            { "bitwarden-client-name", "web" },
            { "bitwarden-client-version", "2026.3.0" },
        };

        auto res = vaultClient->Delete("/api/ciphers/" + uuid + "/attachment/" + attachmentID, headers);

        if (!res) {
            logger->error("removeAttachment request failed");
            return false;
        }
        if (res->status != 200) {
            logger->error("removeAttachment failed: {}", res->status);
            return false;
        }

        return true;
    }

    std::optional<std::pair<std::string, nlohmann::json>> VaultNetwork::DownloadAttachment(std::string uuid, std::string attachmentID, 
        std::string accessString, std::function<void(float)> onProgress) {
        httplib::Headers headers = {
            { "authorization", "Bearer " + accessString },
            { "Content-Type", "application/json" },
            { "bitwarden-client-name", "web" },
            { "bitwarden-client-version", "2026.3.0" },
        };

        auto res = vaultClient->Get("/api/ciphers/" + uuid + "/attachment/" + attachmentID, headers);

        if (!res) {
            logger->error("downloadAttachment request failed");
            return std::nullopt;
        }
        if (res->status != 200) {
            logger->error("downloadAttachment failed: {}", res->status);
            return std::nullopt;
        }

        auto body = nlohmann::json::parse(res->body);

        if (!body.contains("url") || !body["url"].is_string()) {
            return std::nullopt;
        }
        if (!body.contains("fileName") || !body["fileName"].is_string()) {
            return std::nullopt;
        }
        if (!body.contains("key") || !body["key"].is_string()) {
            return std::nullopt;
        }

        auto dlres = vaultClient->Get(body["url"], headers,
            [&onProgress](uint64_t current, uint64_t total) -> bool {
                if (onProgress && total > 0) {
                    onProgress(static_cast<float>(current) / static_cast<float>(total));
                }
                return true;
            });

        if (!dlres) {
            logger->error("downloadAttachment request failed");
            return std::nullopt;
        }
        if (dlres->status != 200) {
            logger->error("downloadAttachment failed: {}", dlres->status);
            return std::nullopt;
        }

        std::string buf = dlres->body;
        if (buf.size() < 1 + 16 + 32 + 1) {
            logger->error("Blob too short after decode: {}", buf.size());
            return std::nullopt;
        }
        if (buf[0] != 0x02) {
            logger->error("Unexpected enc type: 0x{:02x}", buf[0]);
            return std::nullopt;
        }

        return std::make_pair(std::move(buf), std::move(body));
    }

    std::optional<nlohmann::json> VaultNetwork::CreateFolder(std::string encryptedFolderName, std::string accessString) {
        httplib::Headers headers = {
            { "authorization", "Bearer " + accessString },
            { "Content-Type", "application/json" },
            { "bitwarden-client-name", "web" },
            { "bitwarden-client-version", "2026.3.0" },
        };

        auto res = vaultClient->Post("/api/folders", headers, "{\"name\": \"" + encryptedFolderName + "\"}", "application/json");

        if (!res) {
            logger->error("createFolder request failed");
            return std::nullopt;
        }
        if (res->status != 200) {
            logger->error("createFolder failed: {}", res->status);
            return std::nullopt;
        }

        return nlohmann::json::parse(res->body);
    }

    std::optional<nlohmann::json> VaultNetwork::RenameFolder(std::string folderUUID, std::string encryptedFolderName, 
        std::string accessString) {
        httplib::Headers headers = {
            { "authorization", "Bearer " + accessString },
            { "Content-Type", "application/json" },
            { "bitwarden-client-name", "web" },
            { "bitwarden-client-version", "2026.3.0" },
        };

        auto res = vaultClient->Put("/api/folders/" + folderUUID, headers, "{\"name\": \"" + encryptedFolderName + "\"}", "application/json");

        if (!res) {
            logger->error("renameFolder request failed");
            return std::nullopt;
        }
        if (res->status != 200) {
            logger->error("renameFolder failed: {}", res->status);
            return std::nullopt;
        }

        return nlohmann::json::parse(res->body);
    }

    bool VaultNetwork::DeleteFolder(std::string folderUUID, std::string accessString) {
        httplib::Headers headers = {
            { "authorization", "Bearer " + accessString },
            { "Content-Type", "application/json" },
            { "bitwarden-client-name", "web" },
            { "bitwarden-client-version", "2026.3.0" },
        };

        auto res = vaultClient->Delete("/api/folders/" + folderUUID, headers);

        if (!res) {
            logger->error("deleteFolder request failed");
            return false;
        }
        if (res->status != 200) {
            logger->error("deleteFolder failed: {}", res->status);
            return false;
        }

        return true;
    }

    std::optional<std::vector<uint8_t>> VaultNetwork::DownloadIcon(std::string url) {
        std::string uri = url;
        if (url.starts_with("https://")) {
            uri = url.substr(8);
        } else if (url.starts_with("http://")) {
            uri = url.substr(7);
        }

        auto res = iconClient->Get("/" + uri + "/icon.png");

        if (!res) {
            logger->error("downloadIcon request failed");
            return std::nullopt;
        }
        if (res->status != 200) {
            logger->error("downloadIcon failed: {}", res->status);
            return std::nullopt;
        }

        return std::vector<uint8_t>(res->body.begin(), res->body.end());
    }

    VaultConnectivity VaultNetwork::getConnectivity() {
        return connectivity;
    }
}