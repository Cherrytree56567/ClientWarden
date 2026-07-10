#pragma once
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/basic_file_sink.h>
#include "VaultCrypto/VaultCrypto.h"
#include "VaultNetwork/VaultNetwork.h"
#include "VaultSession/VaultSession.h"

namespace ClientWarden {
    enum class AuthState {
        Unknown,
        LoggedOut,
        Unlockable,
        WaitingForTOTP,
        WaitingForDeviceVerif,
        Unlocked
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

        bool Login(std::string email, std::string password);
        bool Login(std::string code);

        bool Unlock(std::string password);

        bool Lock();

        bool Sync();

        void SetUris(std::string vaultUri, std::string mainUri, std::string apiUri, std::string iconUri, std::string wssUri);

        Botan::secure_vector<std::string> GetFolders();

        bool UpdateItem(nlohmann::json encryptedData);

        bool NewItem(nlohmann::json encryptedData);
        bool UpdateItem(nlohmann::json encryptedData);
        bool DeleteItem(std::string uuid);
        bool SoftDeleteItem(std::string uuid);
        bool RestoreItem(std::string uuid);
        std::optional<std::string> AddAttachment(std::string uuid, std::string& encryptedFileContents, std::string& encryptedFileName, 
            std::function<void(float)> onProgress = nullptr);
        bool RemoveAttachment(std::string uuid, std::string attachmentID);
        std::optional<std::string> DownloadAttachment(std::string uuid, std::string attachmentID, std::filesystem::path savePath
            std::function<void(float)> onProgress = nullptr, Botan::secure_vector<uint8_t> cipEnc, Botan::secure_vector<uint8_t> cipMac);
        std::optional<std::string> CreateFolder(std::string encryptedFolderName);
        bool RenameFolder(std::string folderUUID, std::string encryptedFolderName);
        bool DeleteFolder(std::string folderUUID);

        VaultSession session;
        VaultCrypto crypto;
        VaultNetwork network;
    private:
        AuthState state;

        Storage storage;

        inline static std::shared_ptr<spdlog::logger> logger;
    };
}