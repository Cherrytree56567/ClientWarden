#include "Vault.h"

namespace ClientWarden::Vault {
    Vault::Vault() {
        if (!logger) {
            spdlog::set_pattern("[%H:%M:%S] [%n] [%^---%L---%$] [thread %t] %v");

            auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
            auto file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(storage.path.string() + "/cw.log", true);

            logger = std::make_shared<spdlog::logger>("ClientWarden::Vault", spdlog::sinks_init_list{console_sink, file_sink});
            logger->set_level(spdlog::level::trace);
            logger->flush_on(spdlog::level::trace);
            spdlog::register_logger(logger);
        }
    }

    void Vault::SetUris(std::string vaultUri, std::string mainUri, std::string apiUri, std::string iconUri) {
        authData["vaultURL"] = vaultUri;
        authData["mainURL"] = mainUri;
        authData["apiURL"] = apiUri;
        authData["iconURL"] = iconUri;
        authData["websURL"] = "wss://vwprod-457fe78y7u.tail24588b.ts.net";
    }

    Vault::~Vault() {
        stopRefreshThread();
        stopWSSLoop();
        spdlog::shutdown();
    }

    Vault& Vault::Instance() {
        static Vault inst;
        return inst;
    }

    std::string Vault::GetName() {
        return vaultData["profile"]["name"];
    }

    std::string Vault::downloadIcon(std::string url) {
        std::vector<uint8_t> urlVec(url.begin(), url.end());
        std::string b64Url = b64Encode(urlVec)  + ".png";
        if (!storage.exists(b64Url)) {
            auto iconDl = OnlineDownloadIcon(url);
            if (!iconDl) {
                logger->error("Failed to download icon");
                return "";
            }
            std::vector<uint8_t> iconCont = iconDl.value();
            storage.write(b64Url, iconCont);
            return (storage.path / std::filesystem::path(b64Url)).string();
        } else {
            return (storage.path / std::filesystem::path(b64Url)).string();
        }
    }

    std::vector<std::string> Vault::GetFolders() {
        /*
         * Secret Data
        */
        std::vector<std::string> folders;

        if (!vaultData.contains("folders") || !vaultData["folders"].is_array()) return folders;

        for (auto& folder : vaultData["folders"]) {
            folders.push_back(folder["id"]);
        }

        return folders;
    }

    std::expected<nlohmann::json, NetworkState> Vault::UpdateItem(nlohmann::json cipher) {
        nlohmann::json onlCipBody;
        onlCipBody["id"] = cipher["id"];
        onlCipBody["encryptedFor"] = cipher["id"];
        onlCipBody["favorite"] = cipher["favorite"];
        onlCipBody["folderId"] = cipher["folderId"];
        onlCipBody["lastKnownRevisionDate"] = cipher["revisionDate"];
        onlCipBody["name"] = cipher["name"];
        onlCipBody["notes"] = cipher["notes"];
        onlCipBody["organizationId"] = cipher["organizationId"];
        onlCipBody["reprompt"] = cipher["reprompt"];
        onlCipBody["type"] = cipher["type"];

        if (cipher.contains("login") && !cipher["login"].is_null()) {
            onlCipBody["login"] = cipher["login"];
        }
        if (cipher.contains("card") && !cipher["card"].is_null()) {
            onlCipBody["card"] = cipher["card"];
        }
        if (cipher.contains("identity") && !cipher["identity"].is_null()) {
            onlCipBody["identity"] = cipher["identity"];
        }
        if (cipher.contains("secureNote") && !cipher["secureNote"].is_null()) {
            onlCipBody["secureNote"] = cipher["secureNote"];
        }
        if (cipher.contains("sshKey") && !cipher["sshKey"].is_null()) {
            onlCipBody["sshKey"] = cipher["sshKey"];
        }

        if (cipher.contains("fields") && !cipher["fields"].is_null()) {
            onlCipBody["fields"] = cipher["fields"];
        }

        return OnlineUpdateItem(onlCipBody);
    }

    /*
    * If an item is added locally, then it will have
    * a createdOffline Flag.
    * If an item is changed locally, then it will have
    * a higher revisionData
    * If an item is deleted locally, the id will be in 
    * a deletedCiphers key which stores an ID of all deleted
    * ciphers until they are deleted in the cloud.
    * If an item is added online, then it will be synced
    * If an item is modified online, then it will have a 
    * higher revision date and will be synced
    * If an item is deleted online, then the local one will not
    * have a createdOnline Flag, and so it will be deleted locally
    * First check if there are items in deletedCiphers
    *  - If there are, then delete them online
    * First Iterate through localVault:
    *  - If an item has createdOffline, then it will be synced to 
    *    online
    *  - Check if cipher exists online
    *  - If a cipher exists online, but the local revisionDate is newer
    *    - Update Online
    *  - If a cipher exists online, but the online revisionDate is newer
    *    - Overwrite Local
    *  - If a cipher doesnt exist online, and doesnt have createdOffline,
    *    - Delete Locally
    * Iterate Online Vault
    *  - If cipher exists online but not locally and Id isn't in deletedCiphers
    *    - Add Locally
    * Save Vault
    */
    NetworkState Vault::Sync() {
        if (!checkConnectivity()) {
            if (OnError) {
                OnError("Failed to connect to Server");
            }
            logger->warn("No Internet");
            return NetworkState::Failed;
        }
        if (!checkAccessTokenValidity()) {
            if (OnError) {
                OnError("Invalid Access Token");
            }
            logger->warn("Invalid Access Token");
            return NetworkState::InvalidAccessToken;
        }

        httplib::Client client(authData["vaultURL"]);

        httplib::Headers headers = {
            { "authorization", "Bearer " + authData["accessString"].get<std::string>() },
            { "Accept", "application/json" },
            { "bitwarden-client-name", "web" },
            { "bitwarden-client-version", "2026.3.0" },
        };

        auto res = client.Get("/api/sync", headers);

        if (!res) {
            if (OnError) {
                OnError("Failed to Sync");
            }
            logger->error("sync request failed");
            return NetworkState::Failed;
        }
        if (res->status != 200) {
            if (OnError) {
                OnError("Failed to Sync");
            }
            logger->error("sync failed: {}", res->status);
            return NetworkState::Failed;
        }

        auto body = nlohmann::json::parse(res->body);

        if (!storage.exists("vault.json")) {
            storage.write("vault.json", body.dump(2));
            vaultData = body;
            return NetworkState::Success;
        }

        if (!vaultData.contains("deletedCiphers")) {
            vaultData["deletedCiphers"] = nlohmann::json::array();
        }
        if (!vaultData.contains("deletedFolders")) {
            vaultData["deletedFolders"] = nlohmann::json::array();
        }

        std::vector<std::string> pendingFolderDeletes;
        for (auto& id : vaultData["deletedFolders"]) {
            pendingFolderDeletes.push_back(id.get<std::string>());
        }

        auto& deletedFolders = vaultData["deletedFolders"];
        for (auto it = deletedFolders.begin(); it != deletedFolders.end();) {
            auto hr = OnlineDeleteFolder(it->get<std::string>());
            if (hr != NetworkState::Success) {
                if (OnError) {
                    OnError("Failed to Sync Folder");
                }
                logger->warn("Failed to Delete Online Folder");
                return hr;
            }
            it = deletedFolders.erase(it);
        }

        std::vector<std::string> localFolderIds;
        std::vector<std::string> removalFolderIds;

        for (auto& folder : vaultData["folders"]) {
            if (!folder.contains("id")) {
                continue;
            }

            localFolderIds.push_back(folder["id"]);

            nlohmann::json onlineFolder;
            bool foundOnlineFolder = false;

            for (auto& onl : body["folders"]) {
                if (onl.contains("id")) {
                    std::string onlineId = onl["id"];
                    std::string localId = folder["id"];
                    if (onlineId == localId) {
                        foundOnlineFolder = true;
                        onlineFolder = onl;
                        break;
                    }
                }
            }

            if (foundOnlineFolder) {
                std::time_t localRevDate = BitwardenTime(folder["revisionDate"]);
                std::time_t onlineRevDate = BitwardenTime(onlineFolder["revisionDate"]);

                if (localRevDate > onlineRevDate) {
                    /*
                    * Update Online
                    */
                    auto hr = OnlineRenameFolder(folder["id"], folder["name"]);
                    if (!hr) {
                        if (OnError) {
                            OnError("Failed to Sync Folder");
                        }
                        logger->warn("Failed to Update Online Folder");
                        return hr.error();
                    }
                    continue;
                } else if (onlineRevDate > localRevDate) {
                    /*
                    * Overwrite Local
                    */
                    folder = onlineFolder;
                    continue;
                }
            }

            if (!foundOnlineFolder) {
                /*
                * Delete Locally
                */
                removalFolderIds.push_back(folder["id"]);
                continue;
            }
        }

        auto& folders = vaultData["folders"];
        for (auto it = folders.begin(); it != folders.end();) {
            if (!it->contains("id") || !(*it)["id"].is_string()) {
                ++it;
                continue;
            }

            std::string id = (*it)["id"].get<std::string>();

            if (std::find(removalFolderIds.begin(), removalFolderIds.end(), id) != removalFolderIds.end()) {
                it = folders.erase(it);
            } else {
                ++it;
            }
        }

        for (auto& cipher : body["folders"]) {
            std::string id = cipher["id"].get<std::string>();
            if (std::find(localFolderIds.begin(), localFolderIds.end(), id) == localFolderIds.end()) {
                if (std::find(pendingFolderDeletes.begin(), pendingFolderDeletes.end(), id) == pendingFolderDeletes.end()) {
                    /*
                    * Add Locally
                    */
                    vaultData["folders"].push_back(cipher);
                }
            }
        }

        std::vector<std::string> pendingDeletes;
        for (auto& id : vaultData["deletedCiphers"]) {
            pendingDeletes.push_back(id.get<std::string>());
        }

        auto& deletedCiphers = vaultData["deletedCiphers"];
        for (auto it = deletedCiphers.begin(); it != deletedCiphers.end();) {
            auto hr = OnlineDeleteItem(it->get<std::string>());
            if (hr != NetworkState::Success) {
                if (OnError) {
                    OnError("Failed to Sync Item");
                }
                logger->warn("Failed to Delete Online Item");
                return hr;
            }
            it = deletedCiphers.erase(it);
        }

        std::vector<std::string> localIds;
        std::vector<std::string> removalIds;

        for (auto& cipher : vaultData["ciphers"]) {
            if (!cipher.contains("id")) {
                continue;
            }

            localIds.push_back(cipher["id"]);

            if (cipher.contains("createdOffline")) {
                if (cipher["createdOffline"] == true) {
                    /*
                    * Sync Online
                    */
                    auto hr = OnlineNewItem(cipher);
                    if (!hr) {
                        if (OnError) {
                            OnError("Failed to Sync Item");
                        }
                        logger->warn("Failed to Create Online Item");
                        return hr.error();
                    }
                    cipher["createdOffline"] = false;
                    continue;
                }
            }

            nlohmann::json onlineCipher;
            bool foundOnlineCipher = false;

            for (auto& onl : body["ciphers"]) {
                if (onl.contains("id")) {
                    std::string onlineId = onl["id"];
                    std::string localId = cipher["id"];
                    if (onlineId == localId) {
                        foundOnlineCipher = true;
                        onlineCipher = onl;
                        break;
                    }
                }
            }

            if (foundOnlineCipher) {
                std::time_t localRevDate = BitwardenTime(cipher["revisionDate"]);
                std::time_t onlineRevDate = BitwardenTime(onlineCipher["revisionDate"]);

                if (localRevDate > onlineRevDate) {
                    /*
                    * Update Online
                    */
                    auto hr = UpdateItem(cipher);
                    if (!hr) {
                        if (OnError) {
                            OnError("Failed to Sync Item");
                        }
                        logger->warn("Failed to Create Online Item");
                        return hr.error();
                    }
                    continue;
                } else if (onlineRevDate > localRevDate) {
                    /*
                    * Overwrite Local
                    */
                    cipher = onlineCipher;
                    continue;
                }
            }

            if (!foundOnlineCipher) {
                if (cipher.contains("createdOffline")) {
                    if (cipher["createdOffline"] == true) {
                        continue;
                    }
                }
                /*
                * Delete Locally
                */
                removalIds.push_back(cipher["id"]);
                continue;
            }
        }

        auto& ciphers = vaultData["ciphers"];
        for (auto it = ciphers.begin(); it != ciphers.end();) {
            if (!it->contains("id") || !(*it)["id"].is_string()) {
                ++it;
                continue;
            }

            std::string id = (*it)["id"].get<std::string>();

            if (std::find(removalIds.begin(), removalIds.end(), id) != removalIds.end()) {
                it = ciphers.erase(it);
            } else {
                ++it;
            }
        }

        for (auto& cipher : body["ciphers"]) {
            std::string id = cipher["id"].get<std::string>();
            if (std::find(localIds.begin(), localIds.end(), id) == localIds.end()) {
                if (std::find(pendingDeletes.begin(), pendingDeletes.end(), id) == pendingDeletes.end()) {
                    /*
                    * Add Locally
                    */
                    vaultData["ciphers"].push_back(cipher);
                }
            }
        }

        storage.write("vault.json", vaultData.dump(2));

        return NetworkState::Success;
    }

    void Vault::websocketLoop() {
        std::string wsUri = authData["websURL"].get<std::string>() + "/notifications/hub";

        httplib::Headers headers = {
            { "Authorization", "Bearer " + authData["accessString"].get<std::string>() }
        };

        httplib::ws::WebSocketClient ws(wsUri, headers);
        
        if (!ws.connect()) {
            if (OnError) {
                OnError("Websocket failed");
            }
            logger->error("Websocket failed");
            return;
        }

        ws.send("{\"protocol\":\"messagepack\",\"version\":1}\x1e");

        std::string msg;

        while (ws.read(msg)) {
            if (!shouldWSS) {
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

            switch (notifyType) {
                case 0: 
                    /*
                     * Cipher is Updated
                    */
                    Sync();
                    break;
                case 1:
                    /*
                     * Cipher is created
                    */
                   Sync();
                   break;
                case 2:
                    /*
                     * Cipher is deleted
                    */
                    Sync();
                    break;
                case 3:
                    /*
                     * Folder is deleted
                    */
                    Sync();
                    break;
                case 4:
                    /*
                     * All Ciphers changed
                     * TODO: Update whole vault.json file
                    */
                    break;
                case 5:
                    /*
                     * Whole Vault Changed
                     * TODO: Update whole vault.json file
                    */
                    break;
                case 6:
                    /*
                     * Org Keys Changed
                     * TODO: Update Org Keys
                    */
                    break;
                case 7:
                    /*
                     * Folder is created
                    */
                    Sync();
                    break;
                case 8:
                    /*
                     * Folder is updated
                    */
                    Sync();
                    break;
                case 9:
                    /*
                     * Cipher is binned
                    */
                    Sync();
                    break;
                case 10:
                    /*
                     * Account settings changed
                     * TODO: Update data.json
                    */
                    break;
                case 11:
                    /*
                     * Log out
                     * TODO: Log out
                    */
                    break;
                default:
                    if (OnError) {
                        OnError("Unknown WebSocket Type");
                    }
                    logger->info("Unhandled type: {}", notifyType);
                    break;
            }

            logger->info(msg);
        }
    }

    void Vault::startWSSLoop() {
        if (shouldWSS == false) {
            shouldWSS = true;

            if (wssThread.joinable()) {
                wssThread.join();
            }

            wssThread = std::thread(&Vault::websocketLoop, this);
        }
    }

    void Vault::stopWSSLoop() {
        shouldWSS = false;

        if (wssThread.joinable()) {
            wssThread.join();
        }
    }
}