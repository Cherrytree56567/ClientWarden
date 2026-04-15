#pragma once
#include <httplib.h>
#include <openssl/kdf.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <spdlog/spdlog.h>
#include <openssl/crypto.h>
#include <nlohmann/json.hpp>
#include <string>
#include <expected>
#include "Storage/Storage.h"
#include "CommonVault.h"
#include "VaultUtils/VaultUtils.h"

namespace ClientWarden::Vault {
    /*
    * On First Time:
    * Login
    *  - submitTOTP
    *  - submitDeviceVerify
    * Get InternalKey and masterPasswordHash
    * Full Sync
    * Get macKey and encKey
    * 
    * On Unlock:
    * Get InternalKey and masterPasswordHash
    * Get macKey and encKey
    * 
    * On Startup:
    * run hasStoredSession
    *  - If false, its the first time
    *  - If true, then 
    *    - load data.json and vault.json
    *    - run Unlock
    * Load refresh Thread
    * 
    * On Lock:
    *  - Clean encKey and macKey and masterPasswordHash and internalKey
    * 
    * Timeline:
    * Implement create, modify, delete, restore, perm del item - Done
    * Implement Get, Create, Rename, Delete Folder - Done
    * Implement Get All Items, Items By UUID, Search Item, Get Items by Folder, Get Favorites - Done
    * Implement Get Card, Identity, SSHKey, Login, Note - Done
    * Implement Get Password History - Done
    * Implement Copy to Clipboard - To be impl'd in UI
    * Implement Generate Password
    */
    class Vault {
    public:
        Vault();
        ~Vault();

        AuthState Login(std::string& email, std::string& password);
        AuthState submitTOTP(std::string& totp);
        AuthState submitDeviceVerify(std::string& code);
        NetworkState postLogin();

        void Unlock(std::string& password);

        bool hasStoredSession();
        void loadFiles();

        NetworkState Sync();

        void startRefreshThread();
        void stopRefreshThread();

    public:
        NetworkState preLogin(std::string& email);
        AuthState getToken();
        AuthState getTokenWTotp(std::string& totp);
        AuthState getTokenWDeviceVerify(std::string& code);
        bool checkConnectivity();
        bool checkAccessTokenValidity();

        /*
        * These internal functions do not encrypt anything, and
        * data sent to these functions must be encrypted with the
        * exception of uuids
        */
        std::expected<nlohmann::json, NetworkState> OnlineNewItem(nlohmann::json encryptedData);
        std::expected<nlohmann::json, NetworkState> OnlineUpdateItem(nlohmann::json encryptedData);
        NetworkState OnlineDeleteItem(std::string uuid);
        NetworkState OnlineSoftDeleteItem(std::string uuid);
        std::expected<nlohmann::json, NetworkState> OnlineAddAttachment(std::string uuid, std::string encryptedFileContents, std::string encryptedFileName);
        NetworkState OnlineRemoveAttachment(std::string uuid, std::string attachmentID);
        std::expected<std::string, NetworkState> OnlineDownloadAttachment(std::string uuid, std::string attachmentID);
        std::expected<nlohmann::json, NetworkState> OnlineCreateFolder(std::string encryptedFolderName);
        std::expected<nlohmann::json, NetworkState> OnlineRenameFolder(std::string folderUUID, std::string encryptedFolderName);
        NetworkState OnlineDeleteFolder(std::string folderUUID);
        std::expected<std::vector<uint8_t>, NetworkState> OnlineDownloadIcon(std::string url);

        std::vector<uint8_t> makeKey(const std::string& password, const std::string& salt, int iterations);
        std::string cipherString(int encryptionType, const std::string& iv, const std::string& ct, const std::string& mac);
        std::string makeEncKey(const std::vector<uint8_t>& key);
        std::string hashedPassword(const std::string& password, const std::string& salt, int iterations);
        bool macsEqual(const std::vector<uint8_t>& macKey, const std::vector<uint8_t>& mac1, const std::vector<uint8_t>& mac2);
        std::vector<uint8_t> InternalDecrypt(const std::string& str, const std::vector<uint8_t>& key, const std::vector<uint8_t>& macKey);
        std::string InternalEncrypt(const std::vector<uint8_t>& pt, const std::vector<uint8_t>& key, const std::vector<uint8_t>& macKey);
        std::vector<uint8_t> hkdfStretch(const std::string& info);
        std::pair<std::vector<uint8_t>, std::vector<uint8_t>> generateEncMacKeys();
        std::string getUriChecksum(std::string& uri, std::vector<uint8_t> itemEncKey, std::vector<uint8_t> itemMacKey);
        std::string Encrypt(std::string str, const std::vector<uint8_t>& key, const std::vector<uint8_t>& macKey);
        std::string Decrypt(std::string str, const std::vector<uint8_t>& key, const std::vector<uint8_t>& macKey);
        void getMainKeys();
        std::pair<std::vector<uint8_t>, std::vector<uint8_t>> getKeysFromCipher(std::string mainKey);
        std::string decryptItem(std::string item, std::vector<uint8_t> itemEncKey, std::vector<uint8_t> itemMacKey);

        void refreshLoop();
        void refreshToken();
        bool needsRefresh();

        /*
        * SECRET DATA
        */
        std::vector<uint8_t> internalKey;
        std::string masterPasswordHash;
        std::vector<uint8_t> encKey;
        std::vector<uint8_t> macKey;

        std::thread refreshThread;
        std::atomic<bool> shouldRefresh { false };

        nlohmann::json authData;
        nlohmann::json vaultData;
        Storage storage;
        std::string vaultURL;
        std::string mainURL;
        std::string apiURL;
        std::string iconURL;
    };
}