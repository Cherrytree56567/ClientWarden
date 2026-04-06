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
    void refreshToken();

private:
    std::string b64Encode(const std::vector<uint8_t>& data); // Claude Func
    std::vector<uint8_t> b64Decode(const std::string& data); // Claude Func
    std::time_t BitwardenTime(std::string time); // Not AI Func

    std::vector<uint8_t> makeKey(const std::string& password, const std::string& salt, int iterations);
    std::string cipherString(int encryptionType, const std::string& iv, const std::string& ct, const std::string& mac);
    std::string makeEncKey(const std::vector<uint8_t>& key);
    std::string hashedPassword(const std::string& password, const std::string& salt, int iterations);
    bool macsEqual(const std::vector<uint8_t>& macKey, const std::vector<uint8_t>& mac1, const std::vector<uint8_t>& mac2);
    std::vector<uint8_t> InternalDecrypt(const std::string& str, const std::vector<uint8_t>& key, const std::vector<uint8_t>& macKey);
    std::string InternalEncrypt(const std::vector<uint8_t>& pt, const std::vector<uint8_t>& key, const std::vector<uint8_t>& macKey);

    void newItem(nlohmann::json data);
    void updateItem(nlohmann::json data);
    void deleteItem(std::string uuid);
    void addAttachment(std::string uuid, std::string file);
    void removeAttachment(std::string uuid, std::string attachmentID);
    std::string downloadAttachment(std::string uuid, std::string attachmentID);
    void createFolder(std::string folderName);
    void renameFolder(std::string folderUUID, std::string folderName);
    void deleteFolder(std::string folderUUID);
    std::string downloadIcon(std::string url);

    void preLogin(const std::string& email);
    Errors getToken(std::string code, Type type);

    void refreshLoop();

    std::vector<uint8_t> internalKey;
    std::string masterPasswordHash;
    nlohmann::json jsonData;
    nlohmann::json vaultData;
    Storage storage;
    std::thread refreshThread;
    std::atomic<bool> shouldRefresh { false };
    std::vector<uint8_t> encKey;
    std::vector<uint8_t> macKey;
};