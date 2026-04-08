#pragma once
#include "Storage/Storage.h"
#include <string>
#include <spdlog/spdlog.h>
#include <httplib.h>
#include <nlohmann/json.hpp>
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

enum class AuthState {
    NeedsTOTP,
    NeedsEmailVerification,
    Authenticated,
    Failed
};

enum class NetworkState {
    Success,
    Failed
};

/*
 * On First Time:
 * Login
 *  - submitTOTP
 *  - submitDeviceVerify
 * Get InternalKey and masterPasswordHash
 * Full Sync
 * Get macKey and encKey
 * load Refresh Thread
 * 
 * On Unlock:
 * load data.json and vault.json
 * Get InternalKey and masterPasswordHash
 * Get macKey and encKey
 * load Refresh Thread
 * 
 * On Startup:
 * Check if data.json and vault.json exists
 *  - If not, its the first time
 * Check if accessToken is active
 *  - If not, its the first time
 * Unlock
 * 
 * On Lock:
 *  - Clean encKey and macKey and masterPasswordHash and internalKey
*/
class Vault {
public:
    Vault();

    AuthState Login(std::string& email, std::string& password);
    AuthState submitTOTP(std::string& totp);
    AuthState submitDeviceVerify(std::string& code);

private:
    NetworkState preLogin(std::string& email);
    AuthState getToken();
    AuthState getTokenWTotp(std::string& totp);
    AuthState getTokenWDeviceVerify(std::string& code);

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

    std::string b64Encode(const std::vector<uint8_t>& data); // Claude Func
    std::vector<uint8_t> b64Decode(const std::string& data); // Claude Func
    std::time_t BitwardenTime(std::string time);
    std::string getBitwardenTime();
    std::string uniqueGuid();

    /*
     * SECRET DATA
    */
    std::vector<uint8_t> internalKey;
    std::string masterPasswordHash;
    std::vector<uint8_t> encKey;
    std::vector<uint8_t> macKey;

    nlohmann::json authData;
    Storage storage;
    std::string vaultURL;
};