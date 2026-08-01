#include "Vault.h"
#include "UIBridge/CBridge.h"

/*
 * The code is a bit messier since I had to fix race conditions
*/
namespace ClientWarden {
    /*
     * Check if the user is Logged in or not and
     * load session data.
     * TODO: Add logger stuff, I think I already did this
     * idk tho.
    */
    Vault::Vault() : profile(session.vaultData), crypto(session.encKey, session.macKey, session.internalKey), clipboard(session.settingsData) {
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
            std::unique_lock<std::recursive_mutex> lock(session.authDataMutex);

            std::string accessString = (*session.authData)["accessString"].get<std::string>();
            std::string wssString = (*session.authData)["wssURL"].get<std::string>();

            lock.unlock();

            std::function<void(int notifyType)> websocketLambda = [this](int notifyType) {
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
                        Sync(true);
                        break;
                    case 5:
                        /*
                        * Whole Vault Changed
                        * TODO: Update whole vault.json file
                        */
                        Sync(true);
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
                        Logout();
                        SetLoginPage();
                        break;
                    default:
                        logger->info("Unhandled type: {}", notifyType);
                        break;
                }
            };
            
            bool lastResult = true;

            while (shouldThread) {
                lastResult = network.websocketLoop(websocketLambda, accessString, wssString, shouldThread);
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }

            return lastResult;
        });

        session.refreshThread.setCallback([this](const std::atomic<bool>& shouldThread) {
            while (shouldThread.load()) {
                if (network.getConnectivity() == VaultConnectivity::Offline) {
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                    continue;
                }

                std::unique_lock<std::recursive_mutex> lock_rt(session.authDataMutex);
                std::string needsRefreshTime = (*session.authData)["needsRefreshTime"].get<std::string>();
                lock_rt.unlock();

                std::tm tm = {};
                std::istringstream ss(needsRefreshTime);
                ss >> std::get_time(&tm, "%Y-%m-%d %H:%M:%S");
                tm.tm_isdst = -1;
                std::time_t expiry = std::mktime(&tm);
                std::time_t now = std::time(nullptr);

                if (now >= expiry) {
                    std::unique_lock<std::recursive_mutex> lock_ref(session.authDataMutex);
                    std::string refreshTime = (*session.authData)["refreshToken"].get<std::string>();
                    lock_ref.unlock();

                    std::optional<nlohmann::json> refreshBody = network.refreshToken(refreshTime);

                    if (!refreshBody.has_value()) {
                        std::this_thread::sleep_for(std::chrono::milliseconds(500));
                        continue;
                    }

                    std::unique_lock<std::recursive_mutex> lock_as(session.authDataMutex);
                    (*session.authData)["accessString"] = refreshBody.value()["access_token"];
                    (*session.authData)["expiresIn"] = refreshBody.value()["expires_in"];

                    std::time_t now = std::time(nullptr) + (*session.authData)["expiresIn"].get<int>();
                    std::tm* localTime = std::localtime(&now);

                    std::ostringstream oss;
                    oss << std::put_time(localTime, "%Y-%m-%d %H:%M:%S");
                    (*session.authData)["needsRefreshTime"] = oss.str();

                    storage.write("data.json", session.authData->dump(4));
                    lock_as.unlock();
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            return true;
        });

        session.connectivityThread.setCallback([this](const std::atomic<bool>& shouldThread) {
            while (shouldThread.load()) {
                network.checkConnectivity();
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            return true;
        });

        if (!storage.exists("data.json") || !storage.exists("vault.json")) {
            state = AuthState::LoggedOut;
        } else {
            state = AuthState::Unlockable;
            
            std::unique_lock<std::recursive_mutex> lock_adSet(session.authDataMutex);
            *session.authData = nlohmann::json::parse(storage.read("data.json"));
            lock_adSet.unlock();

            std::unique_lock<std::recursive_mutex> lock_vdset(session.vaultDataMutex);
            *session.vaultData = nlohmann::json::parse(storage.read("vault.json"));
            lock_vdset.unlock();

            std::unique_lock<std::recursive_mutex> lock_check(session.authDataMutex);
            if (!(*session.authData).contains("apiURL") || !(*session.authData).contains("iconURL") || 
                !(*session.authData).contains("mainURL") || !(*session.authData).contains("vaultURL") || 
                !(*session.authData).contains("wssURL")) {
                logger->info("URL Info Not Found in data.json");
                state = AuthState::Failed;
            }
            lock_check.unlock();

            std::unique_lock<std::recursive_mutex> lock_adget(session.authDataMutex);
            std::string vaultURL = (*session.authData)["vaultURL"];
            std::string mainURL = (*session.authData)["mainURL"];
            std::string apiURL = (*session.authData)["apiURL"];
            std::string iconURL = (*session.authData)["iconURL"];
            lock_adget.unlock();

            network.initNetwork(vaultURL, mainURL, apiURL, iconURL);
        }

        if (storage.exists("settings.json")) {
            std::unique_lock<std::recursive_mutex> lock_sdset(session.vaultDataMutex);
            *session.settingsData = nlohmann::json::parse(storage.read("settings.json"));
            lock_sdset.unlock();
        } else {
            std::unique_lock<std::recursive_mutex> lock_sdset(session.vaultDataMutex);
            (*session.settingsData)["clipboardClear"] = 30;

            storage.write("settings.json", session.settingsData->dump(2));
            lock_sdset.unlock();
        }
    }

    Vault::~Vault() {
        Lock();
        session.wssThread.stop();
        session.refreshThread.stop();
        session.connectivityThread.stop();
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

    std::vector<std::string> Vault::getAutoFillCiphers(std::string url) {
        std::vector<std::string> cipherIDs;

        return cipherIDs;
    }

    void Vault::SetUris(std::string vaultUri, std::string mainUri, std::string apiUri, std::string iconUri, std::string wssUri) {
        std::unique_lock<std::recursive_mutex> lock_adset(session.authDataMutex);
        (*session.authData)["vaultURL"] = vaultUri;
        (*session.authData)["mainURL"] = mainUri;
        (*session.authData)["apiURL"] = apiUri;
        (*session.authData)["iconURL"] = iconUri;
        (*session.authData)["wssURL"] = wssUri;
        lock_adset.unlock();

        network.initNetwork(vaultUri, mainUri, apiUri, iconUri);
    }

    /*
     * Since encryption requires a case-sensitive lowercase email
     * as a salt, we must lowercase the email using boost. Then
     * we can run the preLogin to get our KDF Iterations and salt.
    */
    bool Vault::Login(std::string& email, std::string& password) {
        boost::algorithm::to_lower(email);
        
        std::optional<nlohmann::json> preLogin = network.preLogin(email);
        if (!preLogin.has_value()) {
            return false;
        }

        std::unique_lock<std::recursive_mutex> lock_adset(session.authDataMutex);
        (*session.authData)["kdfIterations"] = preLogin.value()["kdfIterations"];
        (*session.authData)["salt"] = email;
        (*session.authData)["email"] = email;
        lock_adset.unlock();

        std::unique_lock<std::recursive_mutex> lock_adget(session.authDataMutex);
        std::string salt = (*session.authData)["salt"];
        int kdfIterations = (*session.authData)["kdfIterations"];
        lock_adget.unlock();

        *session.internalKey = std::move(crypto.makeKey(password, salt, kdfIterations));
        session.masterPasswordHash = crypto.hashedPassword(password, *session.internalKey);

        /*
         * Erase the password safely
         */
        OPENSSL_cleanse(password.data(), password.size());
        password.clear();

        std::optional<nlohmann::json> token = network.getToken(email, session.masterPasswordHash);
        if (token.has_value()) {
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
            if (!token.value().contains("access_token") || !token.value().contains("refresh_token") ||
                !token.value().contains("expires_in")) {
                return false;
            }
            std::unique_lock<std::recursive_mutex> lock_adset1(session.authDataMutex);
            (*session.authData)["accessString"] = token.value()["access_token"];
            (*session.authData)["refreshToken"] = token.value()["refresh_token"];
            (*session.authData)["expiresIn"] = token.value()["expires_in"];

            std::time_t now = std::time(nullptr) + (*session.authData)["expiresIn"].get<int>();
            std::tm* localTime = std::localtime(&now);

            std::ostringstream oss;
            oss << std::put_time(localTime, "%Y-%m-%d %H:%M:%S");
            (*session.authData)["needsRefreshTime"] = oss.str();

            storage.write("data.json", session.authData->dump(2));
            lock_adset1.unlock();

            if (!Sync()) {
                return false;
            }

            std::unique_lock<std::recursive_mutex> lock_vdget(session.vaultDataMutex);
            std::string protectedKey = (*session.vaultData)["profile"]["key"];
            lock_vdget.unlock();

            Botan::secure_vector<uint8_t> stretchedEncKey = crypto.hkdfStretch("enc");
            Botan::secure_vector<uint8_t> stretchedMacKey = crypto.hkdfStretch("mac");

            auto [encKey, macKey] = crypto.getEncMacKey(protectedKey, stretchedEncKey, stretchedMacKey);
        
            *session.encKey = std::move(encKey);
            *session.macKey = std::move(macKey);

            session.wssThread.start();
            session.refreshThread.start();
            session.connectivityThread.start();

            state = AuthState::Unlocked;

            return true;
        } else {
            return false;
        }
    }

    bool Vault::Login(std::string code) {
        std::optional<nlohmann::json> token;

        std::unique_lock<std::recursive_mutex> lock_adget(session.authDataMutex);
        std::string salt = (*session.authData)["salt"];
        lock_adget.unlock();
        
        if (state == AuthState::WaitingForTOTP) {
            token = network.getTokenWTotp(salt, session.masterPasswordHash, code);
        } else if (state == AuthState::WaitingForDeviceVerif) {
            token = network.getTokenWDeviceVerify(salt, session.masterPasswordHash, code);
        } else {
            return false;
        }

        if (token.has_value()) {
            if (!token.value().contains("access_token") || !token.value().contains("refresh_token") ||
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
            std::unique_lock<std::recursive_mutex> lock_adset(session.authDataMutex);
            (*session.authData)["accessString"] = token.value()["access_token"];
            (*session.authData)["refreshToken"] = token.value()["refresh_token"];
            (*session.authData)["expiresIn"] = token.value()["expires_in"];

            std::time_t now = std::time(nullptr) + (*session.authData)["expiresIn"].get<int>();
            std::tm* localTime = std::localtime(&now);

            std::ostringstream oss;
            oss << std::put_time(localTime, "%Y-%m-%d %H:%M:%S");
            (*session.authData)["needsRefreshTime"] = oss.str();

            storage.write("data.json", session.authData->dump(2));
            lock_adset.unlock();

            if (!Sync()) {
                return false;
            }

            std::unique_lock<std::recursive_mutex> lock_vdget(session.vaultDataMutex);
            std::string protectedKey = (*session.vaultData)["profile"]["key"];
            lock_vdget.unlock();

            Botan::secure_vector<uint8_t> stretchedEncKey = crypto.hkdfStretch("enc");
            Botan::secure_vector<uint8_t> stretchedMacKey = crypto.hkdfStretch("mac");

            auto [encKey, macKey] = crypto.getEncMacKey(protectedKey, stretchedEncKey, stretchedMacKey);
        
            *session.encKey = std::move(encKey);
            *session.macKey = std::move(macKey);

            session.wssThread.start();
            session.refreshThread.start();
            session.connectivityThread.start();

            state = AuthState::Unlocked;

            return true;
        } else {
            return false;
        }
    }

    bool Vault::Lock() {
        Botan::secure_scrub_memory(session.internalKey->data(), session.internalKey->size());
        OPENSSL_cleanse(session.masterPasswordHash.data(), session.masterPasswordHash.size());
        Botan::secure_scrub_memory(session.encKey->data(), session.encKey->size());
        Botan::secure_scrub_memory(session.macKey->data(), session.macKey->size());

        session.masterPasswordHash.clear();

        return true;
    }

    bool Vault::Unlock(std::string& password) {
        try {
            std::unique_lock<std::recursive_mutex> lock_adget(session.authDataMutex);
            std::string salt = (*session.authData)["salt"];
            int kdfIterations = (*session.authData)["kdfIterations"];
            lock_adget.unlock();

            *session.internalKey = std::move(crypto.makeKey(password, salt, kdfIterations));
            session.masterPasswordHash = crypto.hashedPassword(password, *session.internalKey);

            /*
            * Erase the password safely
            */
            OPENSSL_cleanse(password.data(), password.size());
            password.clear();

            std::unique_lock<std::recursive_mutex> lock_vdget(session.vaultDataMutex);
            std::string protectedKey = (*session.vaultData)["profile"]["key"];
            lock_vdget.unlock();

            Botan::secure_vector<uint8_t> stretchedEncKey = crypto.hkdfStretch("enc");
            Botan::secure_vector<uint8_t> stretchedMacKey = crypto.hkdfStretch("mac");

            auto [encKey, macKey] = crypto.getEncMacKey(protectedKey, stretchedEncKey, stretchedMacKey);

            Botan::secure_scrub_memory(stretchedEncKey.data(), stretchedEncKey.size());
            Botan::secure_scrub_memory(stretchedMacKey.data(), stretchedMacKey.size());

            *session.encKey = std::move(encKey);
            *session.macKey = std::move(macKey);

            session.wssThread.start();
            session.refreshThread.start();
            session.connectivityThread.start();

            std::jthread t([&] {
                Sync();
            });

            state = AuthState::Unlocked;
            return true;
        } catch (...) {
            return false;
        }
    }

    void Vault::SetScreenshotOption(bool value) {
        std::unique_lock<std::recursive_mutex> lock_sdset(session.vaultDataMutex);
        (*session.settingsData)["allowScreenshots"] = value;
        storage.write("settings.json", session.settingsData->dump(2));
        lock_sdset.unlock();
    }

    bool Vault::GetScreenshotOption() {
        std::unique_lock<std::recursive_mutex> lock_sdget(session.vaultDataMutex);
        if (!session.settingsData->contains("allowScreenshots") || !(*session.settingsData)["allowScreenshots"].is_boolean()) {
            (*session.settingsData)["allowScreenshots"] = false;
            storage.write("settings.json", session.settingsData->dump(2));
        }

        bool result = (*session.settingsData)["allowScreenshots"];

        lock_sdget.unlock();

        return result;
    }

    bool Vault::Logout() {
        try {
            Lock();

            storage.remove("vault.json");
            storage.remove("settings.json");
            storage.remove("data.json");
            storage.remove("cw.log");

            state = AuthState::LoggedOut;
            return true;
        } catch (...) {
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
    bool Vault::Sync(bool fullSync) {
        network.checkConnectivity();
        if (network.getConnectivity() == VaultConnectivity::Offline) {
            return false;
        }

        std::unique_lock<std::recursive_mutex> lock_adget(session.authDataMutex);
        std::string accessString = (*session.authData)["accessString"];
        lock_adget.unlock();

        std::optional<nlohmann::json> vaultResult = network.getVault(accessString);

        if (!vaultResult.has_value()) {
            return false;
        }
        nlohmann::json body = vaultResult.value();

        if (!storage.exists("vault.json") || fullSync) {
            storage.write("vault.json", body.dump(2));

            std::unique_lock<std::recursive_mutex> lock_vdset(session.vaultDataMutex);
            *session.vaultData = body;
            lock_vdset.unlock();

            return true;
        }

        std::unique_lock<std::recursive_mutex> lock_vdsetget(session.vaultDataMutex);
        if (!session.vaultData->contains("deletedCiphers")) {
            (*session.vaultData)["deletedCiphers"] = nlohmann::json::array();
        }
        if (!session.vaultData->contains("deletedFolders")) {
            (*session.vaultData)["deletedFolders"] = nlohmann::json::array();
        }

        std::vector<std::string> pendingFolderDeletes;
        for (auto& id : (*session.vaultData)["deletedFolders"]) {
            pendingFolderDeletes.push_back(id.get<std::string>());
        }

        auto& deletedFolders = (*session.vaultData)["deletedFolders"];
        lock_vdsetget.unlock();

        for (auto it = deletedFolders.begin(); it != deletedFolders.end();) {
            bool result = DeleteFolder(it->get<std::string>());
            if (!result) {
                logger->warn("Failed to Delete Online Folder");
                ++it;
                continue;
            }
            lock_vdsetget.lock();
            it = deletedFolders.erase(it);
            lock_vdsetget.unlock();
        }

        std::vector<std::string> localFolderIds;
        std::vector<std::string> removalFolderIds;

        std::unique_lock<std::recursive_mutex> lock_vdget(session.vaultDataMutex);
        auto& l_folders = (*session.vaultData)["folders"];
        lock_vdget.unlock();

        for (auto& folder : l_folders) {
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
                    bool result = RenameFolder(folder["id"], folder["name"]);
                    if (!result) {
                        logger->warn("Failed to Update Online Folder");
                    }
                    continue;
                } else if (onlineRevDate > localRevDate) {
                    /*
                    * Overwrite Local
                    */
                    lock_vdget.lock();
                    folder = onlineFolder;
                    lock_vdget.unlock();
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

        std::unique_lock<std::recursive_mutex> lock_vdget1(session.vaultDataMutex);
        auto& folders = (*session.vaultData)["folders"];
        lock_vdget1.unlock();

        for (auto it = folders.begin(); it != folders.end();) {
            if (!it->contains("id") || !(*it)["id"].is_string()) {
                ++it;
                continue;
            }

            std::string id = (*it)["id"].get<std::string>();

            if (std::find(removalFolderIds.begin(), removalFolderIds.end(), id) != removalFolderIds.end()) {
                lock_vdget1.lock();
                it = folders.erase(it);
                lock_vdget1.unlock();
            } else {
                ++it;
            }
        }

        for (auto& folder : body["folders"]) {
            if (!folder.contains("id")) {
                continue;
            }

            std::string id = folder["id"].get<std::string>();
            if (std::find(localFolderIds.begin(), localFolderIds.end(), id) == localFolderIds.end()) {
                if (std::find(pendingFolderDeletes.begin(), pendingFolderDeletes.end(), id) == pendingFolderDeletes.end()) {
                    /*
                    * Add Locally
                    */
                    std::unique_lock<std::recursive_mutex> lock_vdset1(session.vaultDataMutex);
                    (*session.vaultData)["folders"].push_back(folder);
                    lock_vdset1.unlock();
                }
            }
        }

        std::vector<std::string> pendingDeletes;

        std::unique_lock<std::recursive_mutex> lock_vdget2(session.vaultDataMutex);
        for (auto& id : (*session.vaultData)["deletedCiphers"]) {
            pendingDeletes.push_back(id.get<std::string>());
        }

        auto& deletedCiphers = (*session.vaultData)["deletedCiphers"];
        lock_vdget2.unlock();

        for (auto it = deletedCiphers.begin(); it != deletedCiphers.end();) {
            bool result = DeleteItem(it->get<std::string>());
            if (!result) {
                logger->warn("Failed to Delete Online Item");
                ++it;
                continue;
            }
            lock_vdget2.lock();
            it = deletedCiphers.erase(it);
            lock_vdget2.unlock();
        }

        std::vector<std::string> localIds;
        std::vector<std::string> removalIds;

        std::unique_lock<std::recursive_mutex> lock_vdget3(session.vaultDataMutex);
        auto& l_ciphers = (*session.vaultData)["ciphers"];
        lock_vdget3.unlock();

        for (auto& cipher : l_ciphers) {
            if (!cipher.contains("id")) {
                continue;
            }

            localIds.push_back(cipher["id"]);

            if (cipher.contains("createdOffline")) {
                if (cipher["createdOffline"] == true) {
                    /*
                    * Sync Online
                    */
                    std::optional<nlohmann::json> result = NewItem(cipher);
                    if (!result.has_value()) {
                        logger->warn("Failed to Create Online Item");
                        continue;
                    }

                    lock_vdget3.lock();
                    cipher["createdOffline"] = false;

                    nlohmann::json r_json = result.value();

                    if (r_json.contains("id")) {
                        cipher["id"] = r_json["id"];
                        localIds.push_back(cipher["id"]);
                    }

                    if (r_json.contains("revisionDate")) {
                        cipher["revisionDate"] = r_json["revisionDate"];
                    }

                    lock_vdget3.unlock();
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
                        logger->warn("Failed to Update Online Item");
                    }
                    continue;
                } else if (onlineRevDate > localRevDate) {
                    /*
                    * Overwrite Local
                    */
                    lock_vdget3.lock();
                    cipher = onlineCipher;
                    lock_vdget3.unlock();
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

        std::unique_lock<std::recursive_mutex> lock_vdget4(session.vaultDataMutex);
        auto& ciphers = (*session.vaultData)["ciphers"];
        lock_vdget4.unlock();

        for (auto it = ciphers.begin(); it != ciphers.end();) {
            if (!it->contains("id") || !(*it)["id"].is_string()) {
                ++it;
                continue;
            }

            std::string id = (*it)["id"].get<std::string>();

            if (std::find(removalIds.begin(), removalIds.end(), id) != removalIds.end()) {
                lock_vdget4.lock();
                it = ciphers.erase(it);
                lock_vdget4.unlock();
            } else {
                ++it;
            }
        }

        for (auto& cipher : body["ciphers"]) {
            if (!cipher.contains("id")) {
                continue;
            }

            std::string id = cipher["id"].get<std::string>();
            if (std::find(localIds.begin(), localIds.end(), id) == localIds.end()) {
                if (std::find(pendingDeletes.begin(), pendingDeletes.end(), id) == pendingDeletes.end()) {
                    /*
                    * Add Locally
                    */
                    std::unique_lock<std::recursive_mutex> lock_vdset1(session.vaultDataMutex);
                    (*session.vaultData)["ciphers"].push_back(cipher);
                    lock_vdset1.unlock();
                }
            }
        }

        /*
         * Purge multiple copies
        */
        std::unordered_map<std::string, std::time_t> newestCipher;
        for (auto& cipher : l_ciphers) {
            if (!cipher.contains("id") || !cipher.contains("revisionDate")) {
                continue;
            }

            std::string id = cipher["id"].get<std::string>();
            std::time_t revDate = BitwardenTime(cipher["revisionDate"]);

            auto found = newestCipher.find(id);
            if (found == newestCipher.end() || revDate > found->second) {
                newestCipher[id] = revDate;
            }
        }

        std::unordered_set<std::string> nonDupCiphers;

        for (auto it = l_ciphers.begin(); it != l_ciphers.end();) {
            if (!it->contains("id") || !(*it)["id"].is_string() || !it->contains("revisionDate")) {
                ++it;
                continue;
            }

            std::string id = (*it)["id"].get<std::string>();
            std::time_t revDate = BitwardenTime((*it)["revisionDate"]);

            if (revDate == newestCipher[id] && !nonDupCiphers.count(id)) {
                nonDupCiphers.insert(id);
                ++it;
            } else {
                lock_vdget3.lock();
                it = l_ciphers.erase(it);
                lock_vdget3.unlock();
            }
        }

        std::unique_lock<std::recursive_mutex> lock_vdset2(session.vaultDataMutex);
        storage.write("vault.json", session.vaultData->dump(2));
        lock_vdset2.unlock();

        return true;
    }

    bool Vault::checkReprompt(std::string password) {
        std::unique_lock<std::recursive_mutex> lock_adget(session.authDataMutex);
        std::string salt = (*session.authData)["salt"];
        int kdfIterations = (*session.authData)["kdfIterations"];
        lock_adget.unlock();
        
        Botan::secure_vector<uint8_t> r_internalKey = std::move(crypto.makeKey(password, salt, kdfIterations));
        std::string r_masterPasswordHash = crypto.hashedPassword(password, r_internalKey);

        if (r_internalKey == *session.internalKey && r_masterPasswordHash == session.masterPasswordHash) {
            return true;
        }

        return false;
    }

    std::vector<std::string> Vault::GetFolders() {
        /*
         * Secret Data
        */
        std::vector<std::string> folders;

        std::unique_lock<std::recursive_mutex> lock_vdget(session.vaultDataMutex);
        bool result = !session.vaultData->contains("folders") || !(*session.vaultData)["folders"].is_array();
        lock_vdget.unlock();

        if (result) {
            return folders;
        }

        std::unique_lock<std::recursive_mutex> lock_vdset(session.vaultDataMutex);
        auto& l_folders = (*session.vaultData)["folders"];
        lock_vdset.unlock();

        for (auto& folder : l_folders) {
            folders.push_back(folder["id"]);
        }

        return std::move(folders);
    }

    std::optional<nlohmann::json> Vault::NewItem(nlohmann::json encryptedData, bool performVaultOps, nlohmann::json vaultOpsData) {
        std::unique_lock<std::recursive_mutex> lock_adget(session.authDataMutex);
        std::string accessString = (*session.authData)["accessString"].get<std::string>();
        lock_adget.unlock();

        std::optional<nlohmann::json> result = network.NewItem(encryptedData, accessString);

        if (performVaultOps) {
            if (!result.has_value()) {
                logger->warn("Failed to add New Item Online");
                vaultOpsData["createdOffline"] = true;

                std::unique_lock<std::recursive_mutex> lock_vdsetget(session.vaultDataMutex);
                (*session.vaultData)["ciphers"].push_back(vaultOpsData);
                storage.write("vault.json", session.vaultData->dump(2));
                lock_vdsetget.unlock();

                return std::nullopt;
            }
            std::unique_lock<std::recursive_mutex> lock_vdsetget(session.vaultDataMutex);
            (*session.vaultData)["ciphers"].push_back(result.value());
            storage.write("vault.json", session.vaultData->dump(2));
            lock_vdsetget.unlock();
        }

        return result;
    }

    bool Vault::UpdateItem(nlohmann::json encryptedData) {
        std::unique_lock<std::recursive_mutex> lock_adget(session.authDataMutex);
        std::string accessString = (*session.authData)["accessString"].get<std::string>();
        lock_adget.unlock();

        std::optional<nlohmann::json> res = network.UpdateItem(encryptedData, accessString);
        if (res.has_value()) {
            return true;
        }

        return false;
    }

    bool Vault::DeleteItem(std::string uuid, bool performVaultOps, nlohmann::json vaultOpsData) {
        std::unique_lock<std::recursive_mutex> lock_adget(session.authDataMutex);
        std::string accessString = (*session.authData)["accessString"].get<std::string>();
        lock_adget.unlock();

        bool result = network.DeleteItem(uuid, accessString);
        if (!result) {
            logger->warn("Failed to Delete Online Item");
            if (vaultOpsData.contains("id")) {
                std::unique_lock<std::recursive_mutex> lock_vdset(session.vaultDataMutex);
                (*session.vaultData)["deletedCiphers"].push_back(vaultOpsData["id"]);
                lock_vdset.unlock();
            }
        }

        std::unique_lock<std::recursive_mutex> lock_vdset(session.vaultDataMutex);
        storage.write("vault.json", session.vaultData->dump(2));
        lock_vdset.unlock();
    }

    bool Vault::SoftDeleteItem(std::string uuid) {
        std::unique_lock<std::recursive_mutex> lock_adget(session.authDataMutex);
        std::string accessString = (*session.authData)["accessString"].get<std::string>();
        lock_adget.unlock();

        return network.SoftDeleteItem(uuid, accessString);
    }

    bool Vault::RestoreItem(std::string uuid) {
        std::unique_lock<std::recursive_mutex> lock_adget(session.authDataMutex);
        std::string accessString = (*session.authData)["accessString"].get<std::string>();
        lock_adget.unlock();

        return network.RestoreItem(uuid, accessString);
    }
    
    std::optional<nlohmann::json> Vault::AddAttachment(std::string uuid, std::string& decryptedFileContents, std::string& decryptedFileName, 
        std::function<void(float)> onProgress) {
        auto [attEncKey, attMacKey] = crypto.generateEncMacKeys();

        Botan::secure_vector<uint8_t> attKey(attEncKey.begin(), attEncKey.end());
        attKey.insert(attKey.end(), attMacKey.begin(), attMacKey.end());

        Botan::secure_vector<uint8_t> cipEncKey = *session.encKey;
        Botan::secure_vector<uint8_t> cipMacKey = *session.macKey;

        std::unique_lock<std::recursive_mutex> lock_vdget(session.vaultDataMutex);
        auto l_ciphers = (*session.vaultData)["ciphers"];
        lock_vdget.unlock();
        
        for (auto& cipher : l_ciphers) {
            if (cipher.contains("id") && cipher["id"] == uuid) {
                if (!cipher["key"].is_null()) {
                    auto [cipEnc, cipMac] = crypto.getEncMacKey(cipher["key"]);
                    cipEncKey = cipEnc;
                    cipMacKey = cipMac;
                    Botan::secure_scrub_memory(cipEnc.data(), cipEnc.size());
                    Botan::secure_scrub_memory(cipMac.data(), cipMac.size());
                }
                break;
            }
        }
        
        std::string attachmentKey = crypto.Encrypt(attKey, cipEncKey, cipMacKey);
        Botan::secure_scrub_memory(attKey.data(), attKey.size());

        Botan::secure_vector<uint8_t> a_encryptedFileContents(decryptedFileContents.begin(), decryptedFileContents.end());
        std::string encryptedFileContents = crypto.EncryptRaw(a_encryptedFileContents, attEncKey, attMacKey);
        Botan::secure_scrub_memory(a_encryptedFileContents.data(), a_encryptedFileContents.size());

        std::string encryptedFileName = crypto.Encrypt(decryptedFileName, cipEncKey, cipMacKey);

        Botan::secure_scrub_memory(attEncKey.data(), attEncKey.size());
        Botan::secure_scrub_memory(attMacKey.data(), attMacKey.size());
        Botan::secure_scrub_memory(cipEncKey.data(), cipEncKey.size());
        Botan::secure_scrub_memory(cipMacKey.data(), cipMacKey.size());

        std::unique_lock<std::recursive_mutex> lock_adget(session.authDataMutex);
        std::string accessString = (*session.authData)["accessString"].get<std::string>();
        lock_adget.unlock();

        std::optional<nlohmann::json> res = network.AddAttachment(uuid, encryptedFileContents, encryptedFileName,
            attachmentKey, accessString, onProgress);

        return res;
    }

    bool Vault::RemoveAttachment(std::string uuid, std::string attachmentID) {
        std::unique_lock<std::recursive_mutex> lock_adget(session.authDataMutex);
        std::string accessString = (*session.authData)["accessString"].get<std::string>();
        lock_adget.unlock();

        return network.RemoveAttachment(uuid, attachmentID, accessString);
    }

    bool Vault::DownloadAttachment(std::string uuid, std::string attachmentID, std::filesystem::path savePath,
        Botan::secure_vector<uint8_t> cipEnc, Botan::secure_vector<uint8_t> cipMac, std::function<void(float)> onProgress) {
        std::unique_lock<std::recursive_mutex> lock_adget(session.authDataMutex);
        std::string accessString = (*session.authData)["accessString"].get<std::string>();
        lock_adget.unlock();

        std::optional<std::pair<std::string, nlohmann::json>> attachment = network.DownloadAttachment(uuid, attachmentID, accessString, 
            onProgress);
        
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

        std::string decBody = crypto.DecryptRaw(vecBuf, decEnc, decMac);

        attachment.value().first.clear();
        Botan::secure_scrub_memory(decEnc.data(), decEnc.size());
        Botan::secure_scrub_memory(decMac.data(), decMac.size());
        Botan::secure_scrub_memory(vecBuf.data(), vecBuf.size());

        storage.write(savePath, decBody);

        decBody.clear();

        return true;
    }

    std::optional<nlohmann::json> Vault::CreateFolder(std::string encryptedFolderName) {
        std::unique_lock<std::recursive_mutex> lock_adget(session.authDataMutex);
        std::string accessString = (*session.authData)["accessString"].get<std::string>();
        lock_adget.unlock();

        return network.CreateFolder(encryptedFolderName, accessString);
    }

    bool Vault::RenameFolder(std::string folderUUID, std::string encryptedFolderName) {
        std::unique_lock<std::recursive_mutex> lock_adget(session.authDataMutex);
        std::string accessString = (*session.authData)["accessString"].get<std::string>();
        lock_adget.unlock();

        return network.RenameFolder(folderUUID, encryptedFolderName, accessString).has_value();
    }

    bool Vault::DeleteFolder(std::string folderUUID) {
        std::unique_lock<std::recursive_mutex> lock_adget(session.authDataMutex);
        std::string accessString = (*session.authData)["accessString"].get<std::string>();
        lock_adget.unlock();

        return network.DeleteFolder(folderUUID, accessString);
    }

    std::optional<std::string> Vault::DownloadIcon(std::string url) {
        Botan::secure_vector<uint8_t> urlVec(url.begin(), url.end());
        std::string b64Url = b64Encode(urlVec)  + ".png";
        std::string failFile = b64Url + ".failed";

        if (network.getConnectivity() == VaultConnectivity::Offline) {
            return std::nullopt;
        }

        if (storage.exists(failFile)) {
            return std::nullopt;
        }

        if (!storage.exists(b64Url)) {
            std::optional<std::vector<uint8_t>> result = network.DownloadIcon(url);
            if (!result.has_value()) {
                logger->error("Failed to download icon");
                storage.write(failFile, std::vector<uint8_t>{});
                return std::nullopt;
            }
            storage.write(b64Url, result.value());
            return (storage.path / std::filesystem::path(b64Url)).string();
        } else {
            return (storage.path / std::filesystem::path(b64Url)).string();
        }
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