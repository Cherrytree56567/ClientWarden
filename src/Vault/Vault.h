#pragma once
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/basic_file_sink.h>
#include "VaultCrypto/VaultCrypto.h"
#include "VaultNetwork/VaultNetwork.h"
#include "VaultSession/VaultSession.h"
#include "VaultProfile/VaultProfile.h"
#include "Storage/Storage.h"

#include "Folder/Folder.h"
#include "CipherQuery/CipherQuery.h"
#include "GenericItem/GenericItemImpl.h"
#include "VaultUtils/VaultUtils.h"
#include "Clipboard/Clipboard.h"

namespace ClientWarden {
    enum class AuthState {
        Unknown,
        LoggedOut,
        Unlockable,
        WaitingForTOTP,
        WaitingForDeviceVerif,
        Unlocked,
        Failed // Vault should never reach this point
    };

    /*
     * On Startup, the vault determines if
     * the user has already logged in, or not
     * and also initializes all member classes
     * 
     * TODO: For me to remember later
     * I had a problem before where I would have
     * to pass Vault to the Generic Item but since
     * Vault was basically doing everything before
     * I wasn't sure how to impl it, bc the best
     * way would be to make a Generic Item would be
     * from the Vault Itself.
     * * So, what if I only pass the Vault Session,
     * Vault Crypto and Vault Network to it *
    */
    class Vault {
    public:
        Vault();
        ~Vault();

        static Vault& Instance();

        bool Login(std::string& email, std::string& password);
        bool Login(std::string code);

        bool Unlock(std::string& password);
        bool Lock();
        bool Logout();

        bool Sync();

        void SetUris(std::string vaultUri, std::string mainUri, std::string apiUri, std::string iconUri, std::string wssUri);

        void SetScreenshotOption(bool value);
        bool GetScreenshotOption();

        template <typename Derived>
        std::shared_ptr<Derived> GetItem(std::string uuid) {
            return std::make_shared<Derived>(*this, uuid);
        }

        template <typename Derived>
        std::shared_ptr<Derived> CreateItem() {
            return std::make_shared<Derived>(*this);
        }
        
        std::shared_ptr<GenericItem> GetItem(std::string uuid);
        std::shared_ptr<Folder> GetFolder(std::string uuid);
        std::shared_ptr<Folder> CreateFolder();
        std::vector<std::string> GetFolders();
        std::shared_ptr<CipherQuery> GetCipherQuery();

        std::optional<nlohmann::json> NewItem(nlohmann::json encryptedData, bool performVaultOps = false, nlohmann::json vaultOpsData = nlohmann::json());
        bool UpdateItem(nlohmann::json encryptedData);
        bool DeleteItem(std::string uuid, bool performVaultOps = false, nlohmann::json vaultOpsData = nlohmann::json());
        bool SoftDeleteItem(std::string uuid);
        bool RestoreItem(std::string uuid);
        std::optional<nlohmann::json> AddAttachment(std::string uuid, std::string& decryptedFileContents, std::string& decryptedFileName, 
            std::function<void(float)> onProgress = nullptr);
        bool RemoveAttachment(std::string uuid, std::string attachmentID);
        bool DownloadAttachment(std::string uuid, std::string attachmentID, std::filesystem::path savePath,
            Botan::secure_vector<uint8_t> cipEnc, Botan::secure_vector<uint8_t> cipMac, std::function<void(float)> onProgress = nullptr);
        std::optional<nlohmann::json> CreateFolder(std::string encryptedFolderName);
        bool RenameFolder(std::string folderUUID, std::string encryptedFolderName);
        bool DeleteFolder(std::string folderUUID);
        std::optional<std::string> DownloadIcon(std::string url);

        VaultSession session;
        VaultCrypto crypto;
        VaultNetwork network;
        VaultProfile profile;
        AuthState state;
        Storage storage;
        Clipboard clipboard;
    };
}