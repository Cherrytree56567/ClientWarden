#include "Vault.h"

namespace ClientWarden {
    /*
     * Check if the user is Logged in or not and
     * load session data.
     * TODO: Add logger stuff
    */
    Vault::Vault() : network(session.authData) {
        if (!logger) {
            spdlog::set_pattern("[%H:%M:%S] [%n] [%^---%L---%$] [thread %t] %v");

            auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
            auto file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(storage.path.string() + "/cw.log", true);

            logger = std::make_shared<spdlog::logger>("ClientWarden::Vault", spdlog::sinks_init_list{console_sink, file_sink});
            logger->set_level(spdlog::level::trace);
            logger->flush_on(spdlog::level::trace);
            spdlog::register_logger(logger);
        }

        session.wssThread.setCallback([this](const std::atomic<bool>& shouldThread) {
            return network.websocketLoop([this](int notifyType) {
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
                        logger->info("Unhandled type: {}", notifyType);
                        break;
                }
            }, (*session.authData)["accessString"].get<std::string>(), (*session.authData)["wssURL"].get<std::string>(), shouldThread);
        });

        session.refreshThread.setCallback([this](const std::atomic<bool>& shouldThread) {
            while (shouldThread.load()) {
                if (network.getConnectivity() == VaultConnectivity::Offline) {
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                    continue;
                }
                std::tm tm = {};
                std::istringstream ss((*session.authData)["needsRefreshTime"].get<std::string>());
                ss >> std::get_time(&tm, "%Y-%m-%d %H:%M:%S");
                tm.tm_isdst = -1;
                std::time_t expiry = std::mktime(&tm);
                std::time_t now = std::time(nullptr);

                if (now >= expiry) {
                    std::optional<nlohmann::json> refreshBody = network.refreshToken();

                    if (!refreshBody.has_value()) {
                        std::this_thread::sleep_for(std::chrono::seconds(1));
                        continue;
                    }

                    (*session.authData)["accessString"] = refreshBody.value()["access_token"];
                    (*session.authData)["expiresIn"] = refreshBody.value()["expires_in"];

                    std::time_t now = std::time(nullptr) + (*session.authData)["expiresIn"].get<int>();
                    std::tm* localTime = std::localtime(&now);

                    std::ostringstream oss;
                    oss << std::put_time(localTime, "%Y-%m-%d %H:%M:%S");
                    (*session.authData)["needsRefreshTime"] = oss.str();

                    storage.write("data.json", session.authData->dump(4));
                }
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
            return true;
        });

        session.connectivityThread.setCallback([this](const std::atomic<bool>& shouldThread) {
            while (shouldThread.load()) {
                network.checkConnectivity();
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
            return true;
        });

        if (!storage.exists("data.json") || !storage.exists("vault.json")) {
            state = AuthState::LoggedOut;
        } else {
            state = AuthState::Unlockable;

            session.authData = std::make_shared<nlohmann::json>(nlohmann::json::parse(storage.read("data.json")));
            session.vaultData = std::make_shared<nlohmann::json>(nlohmann::json::parse(storage.read("vault.json")));
        }

        if (storage.exists("settings.json")) {
            session.settingsData = std::make_shared<nlohmann::json>(nlohmann::json::parse(storage.read("settings.json")));
        } else {
            (*settingsData)["clipboardClear"] = 30;

            storage.write("settings.json", settingsData->dump(2));
        }
    }

    Vault::~Vault() {
        /*
         * Background Threads will be automatically stopped
         * in the VaultSession Destructor
        */
    }

    /*
     * While there can only be 1 instance of
     * Vault, only the UIBridge must use it, 
     * bc there is a possibility for Vault
     * to be expanded to multiple instances
    */
    Vault& Vault::Instance() {
        static Vault inst;
        return inst;
    }

    void Vault::SetUris(std::string vaultUri, std::string mainUri, std::string apiUri, std::string iconUri, std::string wssUri) {
        (*authData)["vaultURL"] = vaultUri;
        (*authData)["mainURL"] = mainUri;
        (*authData)["apiURL"] = apiUri;
        (*authData)["iconURL"] = iconUri;
        (*authData)["wssURL"] = wssUri;
    }

    /*
     * Since encryption requires a case-sensitive lowercase email
     * as a salt, we must lowercase the email using boost. Then
     * we can run the preLogin to get our KDF Iterations and salt.
    */
    bool Vault::Login(std::string email, std::string password) {
        boost::algorithm::to_lower(email);
        
        std::optional<nlohmann::json> preLogin = network.prelogin(email);
        if (preLogin.has_value()) {
            (*authData)["kdfIterations"] = preLogin.value()["kdfIterations"];
            (*authData)["salt"] = email;
            (*authData)["email"] = email;
        }

        session.internalKey = crypto.makeKey(password, (*authData)["salt"], (*authData)["kdfIterations"]);
        session.masterPasswordHash = crypto.hashedPassword(password, internalKey);

        /*
         * Erase the password safely
         */
        OPENSSL_cleanse(password.data(), password.size());
        password.clear();

        std::optional<nlohmann::json> token = getToken(email, session.masterPasswordHash);
        if (token.has_value()) {
            if (!token.value().contains("access_token") || !token.value().contains("refresh_token")
                !token.value().contains("expires_in")) {
                return false;
            }
            if (token.value().contains("error_description")) {
                if (token.value()["error_description"] == "Two factor required.") {
                    state = AuthState::WaitingForTOTP;
                    return true;
                } else if (token.value()["error_description"] == "New device verification required") {
                    state = AuthState::WaitingForDeviceVerif;
                    return true;
                }
                return false;
            }
            authData["accessString"] = token.value()["access_token"];
            authData["refreshToken"] = token.value()["refresh_token"];
            authData["expiresIn"] = token.value()["expires_in"];

            std::time_t now = std::time(nullptr) + authData["expiresIn"].get<int>();
            std::tm* localTime = std::localtime(&now);

            std::ostringstream oss;
            oss << std::put_time(localTime, "%Y-%m-%d %H:%M:%S");
            authData["needsRefreshTime"] = oss.str();

            storage.write("data.json", authData.dump(2));

            session.wssThread.start();
            session.refreshThread.start();
            session.connectivityThread.start();

            state = AuthState::Unlocked;

            return true;
        } else {
            return false;
        }
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
    bool Vault::Sync() {
        if (network.getConnectivity() == VaultConnectivity::Offline) {
            return false;
        }

        std::optional<nlohmann::json> vaultResult = network.getVault((*session.authData)["accessString"]);

        if (!vaultResult.has_value()) {
            return false;
        }
        nlohmann::json body = vaultResult.value();

        /*
         * TODO: Put this into refresh Vault or smth
         * basically start from scratch
        */
        if (!storage.exists("vault.json")) {
            storage.write("vault.json", body.dump(2));
            vaultData = body;
            return true;
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
                logger->warn("Failed to Delete Online Folder");
                return false;
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
                        logger->warn("Failed to Update Online Folder");
                        return false;
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
                logger->warn("Failed to Delete Online Item");
                return false;
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
                        logger->warn("Failed to Create Online Item");
                        return false;
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
                        logger->warn("Failed to Create Online Item");
                        return false;
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

        return true;
    }

    Botan::secure_vector<std::string> Vault::GetFolders() {
        /*
         * Secret Data
        */
        Botan::secure_vector<std::string> folders;

        if (!session.vaultData->contains("folders") || !(*session.vaultData)["folders"].is_array()) {
            return folders;
        }

        for (auto& folder : (*session.vaultData)["folders"]) {
            folders.push_back(folder["id"]);
        }

        return std::move(folders);
    }

    bool Vault::NewItem(nlohmann::json encryptedData) {
        std::optional<nlohmann::json> res = network.NewItem(encryptedData, (*session.authData)["accessString"].get<std::string>());
        if (res.has_value()) {
            return true;
        }

        return false;
    }

    bool Vault::UpdateItem(nlohmann::json encryptedData) {
        std::optional<nlohmann::json> res = network.UpdateItem(encryptedData, (*session.authData)["accessString"].get<std::string>());
        if (res.has_value()) {
            return true;
        }

        return false;
    }

    bool Vault::DeleteItem(std::string uuid) {
        return network.DeleteItem(encryptedData, (*session.authData)["accessString"].get<std::string>());
    }

    bool Vault::SoftDeleteItem(std::string uuid) {
        return network.SoftDeleteItem(encryptedData, (*session.authData)["accessString"].get<std::string>());
    }

    bool Vault::RestoreItem(std::string uuid) {
        return network.RestoreItem(encryptedData, (*session.authData)["accessString"].get<std::string>());
    }
    
    std::optional<std::string> Vault::AddAttachment(std::string uuid, std::string& encryptedFileContents, std::string& encryptedFileName, 
        std::function<void(float)> onProgress = nullptr, std::string attachmentKey) {
        std::optional<nlohmann::json> res = network.AddAttachment(uuid, encryptedFileContents, encryptedFileName,
            (*session.authData)["accessString"].get<std::string>(), onProgress, attachmentKey);
        if (res.has_value()) {
            if (!res.value().contains("attachmentId") || !res.value().contains("cipherResponse")) {
                return std::nullopt;
            }
            if (!res.value()["cipherResponse"].contains("attachments")) {
                return std::nullopt;
            }

            auto attachmentField = res["cipherResponse"]["attachments"];

            if (session.vaultData->contains("ciphers") && (*session.vaultData)["ciphers"].is_array()) {
                for (auto& cipher : (*session.vaultData)["ciphers"]) {
                    if (cipher.contains("id") && cipher["id"] == uuid) {
                        cipher["attachments"] = attachmentField;
                        break;
                    }
                }
            }
            return res.value()["attachmentId"];
        }

        return std::nullopt;
    }

    bool Vault::RemoveAttachment(std::string uuid, std::string attachmentID) {
        return network.RestoreItem(uuid, (*session.authData)["accessString"].get<std::string>());
    }

    bool Vault::DownloadAttachment(std::string uuid, std::string attachmentID, std::filesystem::path savePath
        Botan::secure_vector<uint8_t> cipEnc, Botan::secure_vector<uint8_t> cipMac, std::function<void(float)> onProgress = nullptr) {
        std::optional<std::pair<std::string, nlohmann::json>> attachment = network.DownloadAttachment(uuid, attachmentID, 
            (*session.authData)["accessString"].get<std::string>(), onProgress);
        
        if (!attachment.has_value()) {
            return false;
        }
        std::string attKeyPlain = crypto.DecryptAsStr(attachment.value().second["key"], cipEnc, cipMac);
        if (attKeyPlain.size() != 64) {
            logger->error("Attachment key wrong size: {}", attKeyPlain.size());
            return false;
        }
        Botan::secure_vector<uint8_t> decEnc(attKeyPlain.begin(), attKeyPlain.begin() + 32);
        Botan::secure_vector<uint8_t> decMac(attKeyPlain.begin() + 32, attKeyPlain.end());

        OPENSSL_cleanse(attKeyPlain.data(), attKeyPlain.size());

        Botan::secure_vector<uint8_t> vecBuf(attachment.value().first.begin(), attachment.value().first.end());

        std::string decBody = DecryptRaw(vecBuf, decEnc, decMac);

        attachment.value().first.clear();
        Botan::secure_scrub_memory(decEnc.data(), decEnc.size());
        Botan::secure_scrub_memory(decMac.data(), decMac.size());
        Botan::secure_scrub_memory(vecBuf.data(), vecBuf.size());

        storage.write(savePath, decBody);

        decBody.clear();

        return true;
    }

    std::optional<std::string> Vault::CreateFolder(std::string encryptedFolderName) {
        std::optional<nlohmann::json> res = network.CreateFolder(encryptedFolderName, (*session.authData)["accessString"].get<std::string>());
        if (!res.has_value()) {
            return std::nullopt;
        }

        if (!res.value().contains("id") || !res.value()["id"].is_string()) {
            return std::nullopt;
        }

        return res.value()["id"];
    }

    bool Vault::RenameFolder(std::string folderUUID, std::string encryptedFolderName) {
        return network.RenameFolder(folderUUID, encryptedFolderName, (*session.authData)["accessString"].get<std::string>()).has_value();
    }

    bool Vault::DeleteFolder(std::string folderUUID) {
        return network.RenameFolder(folderUUID, (*session.authData)["accessString"].get<std::string>());
    }

    std::shared_ptr<GenericItem> Vault::GetItem(std::string uuid) {
        return std::make_shared<GenericItem>(*this, uuid);
    }
        
    std::shared_ptr<Folder> Vault::GetFolder(std::string uuid) {
        return std::make_shared<Folder>(*this, uuid);
    }
        
    std::shared_ptr<Folder> Vault::CreateFolder() {
        return std::make_shared<Folder>(*this);
    }
        
    std::shared_ptr<CipherQuery> Vault::GetCipherQuery() {
        return std::make_shared<CipherQuery>(*this);
    }
}