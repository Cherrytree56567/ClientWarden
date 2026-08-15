#pragma once
#define CPPHTTPLIB_EXPECT_100_THRESHOLD 0
#include <httplib.h>
#include <optional>
#include <nlohmann/json.hpp>
#include <msgpack.hpp>

#include "Clientwarden.h"
#include "VaultUtils/VaultUtils.h"

namespace ClientWarden {
    enum class VaultConnectivity {
        Offline,
        Online
    };

    /*
     * Manages the Bitwarden network, such as Syncing
     * updating items, etc
     * The Vault Network doesn't manage or hold any
     * sensitive data
    */
    class VaultNetwork {
    public:
        VaultNetwork();
        ~VaultNetwork();

        void initNetwork(std::string vaultUri, std::string mainUri, std::string apiUri, std::string iconUri);

        std::optional<nlohmann::json> preLogin(std::string& email);
        std::optional<nlohmann::json> getToken(std::string& email, std::string& masterPasswordHash);
        std::optional<nlohmann::json> getTokenWTotp(std::string email, std::string& masterPasswordHash, std::string& totp);
        std::optional<nlohmann::json> getTokenWDeviceVerify(std::string email, std::string& masterPasswordHash, std::string& code);
        bool checkConnectivity();
        bool checkAccessTokenValidity(std::string accessString);
        std::optional<nlohmann::json> refreshToken(std::string refreshToken);
        bool websocketLoop(std::function<void(int notifyType)> onNotification, std::string accessString, std::string wssURL,
            const std::atomic<bool>& shouldThread);
        std::optional<nlohmann::json> getProfile(std::string accessString);

        std::optional<nlohmann::json> getVault(std::string accessToken);

        std::optional<nlohmann::json> NewItem(nlohmann::json encryptedData, std::string accessString);
        std::optional<nlohmann::json> UpdateItem(nlohmann::json encryptedData, std::string accessString);
        bool DeleteItem(std::string uuid, std::string accessString);
        bool SoftDeleteItem(std::string uuid, std::string accessString);
        bool RestoreItem(std::string uuid, std::string accessString);
        bool ArchiveItem(std::string id, std::string accessString);
        bool ArchiveItem(std::vector<std::string> ids, std::string accessString);
        bool UnArchiveItem(std::string id, std::string accessString);
        bool UnArchiveItem(std::vector<std::string> ids, std::string accessString);

        std::optional<nlohmann::json> AddAttachment(std::string uuid, std::string& encryptedFileContents, std::string& encryptedFileName, 
            std::string& attKeyStr, std::string accessString, std::function<void(float)> onProgress = nullptr);
        bool RemoveAttachment(std::string uuid, std::string attachmentID, std::string accessString);
        std::optional<std::pair<std::string, nlohmann::json>> DownloadAttachment(std::string uuid, std::string attachmentID, std::string accessString, 
            std::function<void(float)> onProgress = nullptr);
        
        std::optional<nlohmann::json> CreateFolder(std::string encryptedFolderName, std::string accessString);
        std::optional<nlohmann::json> RenameFolder(std::string folderUUID, std::string encryptedFolderName, std::string accessString);
        bool DeleteFolder(std::string folderUUID, std::string accessString);

        std::optional<std::vector<uint8_t>> DownloadIcon(std::string url);

        VaultConnectivity getConnectivity();
    private:
        std::shared_ptr<httplib::Client> apiClient;
        std::shared_ptr<httplib::Client> vaultClient;
        std::shared_ptr<httplib::Client> iconClient;

        std::mutex apiClientMutex;
        std::mutex vaultClientMutex;
        std::mutex iconClientMutex;

        VaultConnectivity connectivity;
        bool init = false;
    };
}