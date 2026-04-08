#pragma once
#include <boost/algorithm/string.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/lexical_cast.hpp>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/sha.h>
#include <spdlog/spdlog.h>
#include <httplib.h>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include <stdexcept>
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <ctime>
#include "Storage/Storage.h"

enum Errors {
    NeedsOTP,
    NeedsNewDevice,
    UnknownError,
    Success
};

enum Type {
    OTP,
    NewDevice,
    None
};

enum CustomFieldType {
    Text,
    Hidden,
    Checkbox,
    Linked
};

struct Login {
    std::string loginName;
    std::string folderUUID;
    std::string username;
    std::string password;
    std::string totp;
    std::vector<std::string> websites;
    std::string notes;
    std::vector<std::tuple<CustomFieldType, std::string, std::string>> customFields;
};

struct Card {
    std::string& itemName;
    std::string& folderUUID;
    std::string& cardholderName;
    std::string& number;
    std::string& brand;
    std::string& expirationMonth;
    std::string& expirationYear;
    std::string& cvv;
    std::string& notes;
    std::vector<std::tuple<CustomFieldType, std::string&, std::string&>> customFields;
};

struct Identity {
    std::string& itemName;
    std::string& folderUUID;
    std::string& Title;
    std::string& firstName;
    std::string& middleName;
    std::string& lastName;
    std::string& username;
    std::string& company;
    std::string& nationalInsuranceNumber;
    std::string& passportNumber;
    std::string& licenceNumber;
    std::string& email;
    std::string& phone;
    std::string& address1;
    std::string& address2;
    std::string& address3;
    std::string& cityTown;
    std::string& county;
    std::string& postalCode;
    std::string& country;
    std::string& notes;
    std::vector<std::tuple<CustomFieldType, std::string&, std::string&>> customFields;
};

struct Note {
    std::string& itemName;
    std::string& folderUUID;
    std::string& notes;
    std::vector<std::tuple<CustomFieldType, std::string&, std::string&>> customFields;
};

struct SSHKey {
    std::string& itemName;
    std::string& folderUUID;
    std::string& privateKey;
    std::string& publicKey;
    std::string& fingerprint;
    std::string& notes;
    std::vector<std::tuple<CustomFieldType, std::string&, std::string&>> customFields;
};

class Vault {
public:
    Vault();
    ~Vault();

    Errors FirstTimeLogin(std::string& password, std::string& email);
    void FirstTimeLoginOTP(std::string otp);
    void FirstTimeLoginDeviceVerify(std::string code);
    bool login(std::string& password);

    void unlock(std::string& password);

    void sync();
    bool needsRefresh();

    void createLogin(Login& details);

private:
    std::string b64Encode(const std::vector<uint8_t>& data); // Claude Func
    std::vector<uint8_t> b64Decode(const std::string& data); // Claude Func
    std::time_t BitwardenTime(std::string time); // Not AI Func
    std::string getBitwardenTime();
    std::string getUUID();

    std::vector<uint8_t> makeKey(const std::string& password, const std::string& salt, int iterations);
    std::string cipherString(int encryptionType, const std::string& iv, const std::string& ct, const std::string& mac);
    std::string makeEncKey(const std::vector<uint8_t>& key);
    std::string hashedPassword(const std::string& password, const std::string& salt, int iterations);
    bool macsEqual(const std::vector<uint8_t>& macKey, const std::vector<uint8_t>& mac1, const std::vector<uint8_t>& mac2);
    std::vector<uint8_t> InternalDecrypt(const std::string& str, const std::vector<uint8_t>& key, const std::vector<uint8_t>& macKey);
    std::string InternalEncrypt(const std::vector<uint8_t>& pt, const std::vector<uint8_t>& key, const std::vector<uint8_t>& macKey);
    std::vector<uint8_t> hkdfStretch(const std::string& info);
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> generateEncMacKeys();
    std::string getUriChecksum(std::string& uri);
    std::string Encrypt(std::string& str, const std::vector<uint8_t>& key, const std::vector<uint8_t>& macKey);

    void getMainKeys();
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> getKeysFromCipher(std::string mainKey);
    std::string decryptItem(std::string item, std::vector<uint8_t> itemEncKey, std::vector<uint8_t> itemMacKey);

    /*
     * These internal functions do not encrypt anything, and
     * data sent to these functions must be encrypted with the
     * exception of uuids
    */
    nlohmann::json InternalNewItem(nlohmann::json encryptedData);
    nlohmann::json InternalUpdateItem(nlohmann::json encryptedData);
    void InternalDeleteItem(std::string uuid);
    nlohmann::json InternalAddAttachment(std::string uuid, std::string encryptedFileContents, std::string encryptedFileName);
    void InternalRemoveAttachment(std::string uuid, std::string attachmentID);
    std::string InternalDownloadAttachment(std::string uuid, std::string attachmentID);
    nlohmann::json InternalCreateFolder(std::string encryptedFolderName);
    nlohmann::json InternalRenameFolder(std::string folderUUID, std::string encryptedFolderName);
    void InternalDeleteFolder(std::string folderUUID);
    std::vector<uint8_t> InternalDownloadIcon(std::string url);

    void preLogin(const std::string& email);
    Errors getToken(std::string code, Type type);

    void refreshLoop();
    void refreshToken();

    std::vector<uint8_t> internalKey;
    std::string masterPasswordHash;
    nlohmann::json jsonData;
    nlohmann::json vaultData;
    Storage storage;
    std::thread refreshThread;
    std::atomic<bool> shouldRefresh { false };
    std::vector<uint8_t> encKey;
    std::vector<uint8_t> macKey;
    std::atomic<bool> onlineMode { false };
};