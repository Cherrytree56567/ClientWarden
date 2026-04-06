#include "Vault.h"

Vault::Vault() {
    spdlog::set_pattern("[%H:%M:%S] [ClientWarden::Vault] [%^---%L---%$] [thread %t] %v");

    if (storage.exists("data.json")) {
        try {
            jsonData = nlohmann::json::parse(storage.read("data.json"));
        } catch (const nlohmann::json::parse_error& e) {
            spdlog::error("JSON parse error: {}", e.what());
        }
    }
}

Vault::~Vault() {
    shouldRefresh = false;

    if (refreshThread.joinable()) {
        refreshThread.join();
    }
}

void Vault::preLogin(const std::string& email) {
    httplib::Client client("https://vault.bitwarden.com");

    httplib::Headers headers = {
        { "Content-Type", "application/json" },
        { "bitwarden-client-name", "web" },
        { "bitwarden-client-version", "2026.3.0" },
    };

    auto res = client.Post("/identity/accounts/prelogin", headers, "{\"email\":\"" + email + "\"}", "application/json");

    if (!res) {
        spdlog::error("prelogin request failed");
        throw std::runtime_error("prelogin request failed");
    }
    if (res->status != 200) {
        spdlog::error("prelogin failed: {}", res->status);
        throw std::runtime_error("prelogin failed: " + std::to_string(res->status));
    }

    auto body = nlohmann::json::parse(res->body);
    jsonData["kdfIterations"] = body["kdfIterations"];
    jsonData["salt"] = body["salt"];
}

Errors Vault::getToken(std::string code, Type type) {
    boost::uuids::uuid guid = boost::uuids::random_generator()(); 
    std::string uniqueDeviceGuid = boost::lexical_cast<std::string>(guid);

    httplib::Client client("https://vault.bitwarden.com");

    client.set_default_headers({
        { "Accept", "application/json" },
        { "Content-Type", "application/x-www-form-urlencoded; charset=utf-8" },
        { "bitwarden-client-name", "web" },
        { "bitwarden-client-version", "2026.3.0" },
    });

    httplib::Params data;
    data.emplace("grant_type", "password");
    data.emplace("username", jsonData["email"]);
    data.emplace("password", masterPasswordHash);
    data.emplace("scope", "api offline_access");
    data.emplace("client_id", "web");
    data.emplace("deviceType", "10");
    data.emplace("deviceIdentifier", uniqueDeviceGuid);
    data.emplace("deviceName", "firefox");

    if (type == Type::OTP) {
        data.emplace("twoFactorToken", code);
        data.emplace("twoFactorProvider", "0");
        data.emplace("twoFactorRemember", "0");
    } else if (type == Type::NewDevice) {
        data.emplace("newDeviceOtp", code);
    }
    
    auto res = client.Post("/identity/connect/token", data);

    if (res->status == 400) {
        auto body = nlohmann::json::parse(res->body);
        if (body["error_description"] == "Two factor required.") {
            return Errors::NeedsOTP;
        } else if (body["error_description"] == "New device verification required") {
            return Errors::NeedsNewDevice;
        }
    }

    if (!res) {
        spdlog::error("getToken request failed");
        throw std::runtime_error("getToken request failed");
    }
    if (res->status != 200) {
        spdlog::error("getToken failed: {}", res->status);
        throw std::runtime_error("getToken failed: " + std::to_string(res->status));
    }

    auto body = nlohmann::json::parse(res->body);
    jsonData["accessString"] = body["access_token"];
    jsonData["refreshToken"] = body["refresh_token"];
    jsonData["expiresIn"] = body["expires_in"];

    std::time_t now = std::time(nullptr) + jsonData["expiresIn"].get<int>();
    std::tm* localTime = std::localtime(&now);

    std::ostringstream oss;
    oss << std::put_time(localTime, "%Y-%m-%d %H:%M:%S");
    jsonData["needsRefreshTime"] = oss.str();

    storage.write("data.json", jsonData.dump(4));

    return Errors::Success;
}

/*
 * base64-encode a wrapped, stretched password+salt for signup/login
*/
std::string Vault::hashedPassword(const std::string& password, const std::string& salt, int iterations) {
    std::vector<uint8_t> key = makeKey(password, salt, iterations);

    std::vector<uint8_t> hashed(256 / 8);
    PKCS5_PBKDF2_HMAC(
        reinterpret_cast<const char*>(key.data()), key.size(),
        reinterpret_cast<const uint8_t*>(password.data()), password.size(),
        1,
        EVP_sha256(),
        hashed.size(), hashed.data()
    );

    OPENSSL_cleanse(key.data(), key.size());

    return b64Encode(hashed);
}

std::vector<uint8_t> Vault::makeKey(const std::string& password, const std::string& salt, int iterations) {
    std::vector<uint8_t> key(256 / 8);

    int result = PKCS5_PBKDF2_HMAC(
        password.c_str(), password.size(),
        reinterpret_cast<const uint8_t*>(salt.data()), salt.size(),
        iterations,
        EVP_sha256(),
        key.size(), key.data()
    );

    if (result != 1) {
        spdlog::error("PBKDF2 failed");
        throw std::runtime_error("PBKDF2 failed");
    }

    return key;
}

std::string Vault::cipherString(int encryptionType, const std::string& iv, const std::string& ct, const std::string& mac) {
    std::string result = std::to_string(encryptionType) + "." + iv + "|" + ct;

    if (!mac.empty()) {
        result += "|" + mac;
    }

    return result;
}

/*
 * encrypt random bytes with a key to make new encryption key
 * 
 * Had to use Claude to help me translate this from ruby.
*/
std::string Vault::makeEncKey(const std::vector<uint8_t>& key) {
    /*
     * pt[0, 32] becomes the cipher encryption key
     * pt[32, 32] becomes the mac key
    */
    std::vector<uint8_t> pt(64);
    std::vector<uint8_t> iv(16);

    RAND_bytes(pt.data(), pt.size());
    RAND_bytes(iv.data(), iv.size());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        spdlog::error("Failed to create cipher context");
        throw std::runtime_error("Failed to create cipher context");
    }

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data());

    std::vector<uint8_t> ct(pt.size() + 16);

    int len = 0;
    int ct_len = 0;

    EVP_EncryptUpdate(ctx, ct.data(), &len, pt.data(), pt.size());
    ct_len += len;

    EVP_EncryptFinal_ex(ctx, ct.data() + ct_len, &len);
    ct_len += len;

    ct.resize(ct_len);
    EVP_CIPHER_CTX_free(ctx);

    OPENSSL_cleanse(pt.data(), pt.size());

    return cipherString(0, b64Encode(iv), b64Encode(ct), "");
}

/*
 * compare two hmacs, with double hmac verification
 * https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2011/february/double-hmac-verification/
*/
bool Vault::macsEqual(const std::vector<uint8_t>& macKey, const std::vector<uint8_t>& mac1, const std::vector<uint8_t>& mac2) {
    std::vector<uint8_t> hmac1(32);
    std::vector<uint8_t> hmac2(32);
    unsigned int len = 32;

    HMAC(EVP_sha256(),
        macKey.data(), macKey.size(),
        mac1.data(), mac1.size(),
        hmac1.data(), &len);

    HMAC(EVP_sha256(),
        macKey.data(), macKey.size(),
        mac2.data(), mac2.size(),
        hmac2.data(), &len);
    
    return CRYPTO_memcmp(hmac1.data(), hmac2.data(), 32) == 0;
}

/*
 * decrypt a CipherString and return plaintext
*/
std::vector<uint8_t> Vault::InternalDecrypt(const std::string& str, const std::vector<uint8_t>& key, const std::vector<uint8_t>& macKey) {
    if (str[0] != '2') {
        spdlog::error("Implement {} decryption", std::string(1, str[0]));
        throw std::runtime_error("Implement " + std::string(1, str[0]) + " decryption");
    }

    std::string rest = str.substr(2);
    auto split = [](const std::string& s, char delim, int maxParts) {
        std::vector<std::string> parts;
        std::string current;
        for (char c : s) {
            if (c == delim && (int)parts.size() < maxParts - 1) {
                parts.push_back(current);
                current.clear();
            } else {
                current += c;
            }
        }
        parts.push_back(current);
        return parts;
    };

    auto parts = split(rest, '|', 3);
    if (parts.size() != 3) {
        spdlog::error("invalid cipher string format");
        throw std::runtime_error("invalid cipher string format");
    }

    auto iv = b64Decode(parts[0]);
    auto ct = b64Decode(parts[1]);
    auto mac = b64Decode(parts[2]);

    std::vector<uint8_t> ivct;
    ivct.insert(ivct.end(), iv.begin(), iv.end());
    ivct.insert(ivct.end(), ct.begin(), ct.end());

    std::vector<uint8_t> cmac(32);
    unsigned int len = 32;
    HMAC(EVP_sha256(),
        macKey.data(), macKey.size(),
        ivct.data(), ivct.size(),
        cmac.data(), &len);

    if (!macsEqual(macKey, mac, cmac)) {
        spdlog::error("invalid mac");
        throw std::runtime_error("invalid mac");
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        spdlog::error("failed to create cipher context");
        throw std::runtime_error("failed to create cipher context");
    }

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data());

    std::vector<uint8_t> pt(ct.size() + 16);
    int pt_len = 0;

    EVP_DecryptUpdate(ctx, pt.data(), reinterpret_cast<int*>(&len), ct.data(), ct.size());
    pt_len += len;

    EVP_DecryptFinal_ex(ctx, pt.data() + pt_len, (int*)&len);
    pt_len += len;

    EVP_CIPHER_CTX_free(ctx);
    pt.resize(pt_len);
    return pt;
}

std::string Vault::InternalEncrypt(const std::vector<uint8_t>& pt, const std::vector<uint8_t>& key, const std::vector<uint8_t>& macKey) {
    std::vector<uint8_t> iv(16);
    RAND_bytes(iv.data(), iv.size());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        spdlog::error("failed to create cipher context");
        throw std::runtime_error("failed to create cipher context");
    }

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data());

    std::vector<uint8_t> ct(pt.size() + 16);
    int len = 0, ct_len = 0;

    EVP_EncryptUpdate(ctx, ct.data(), &len, pt.data(), pt.size());
    ct_len += len;

    EVP_EncryptFinal_ex(ctx, ct.data() + ct_len, &len);
    ct_len += len;

    ct.resize(ct_len);
    EVP_CIPHER_CTX_free(ctx);

    std::vector<uint8_t> ivct;
    ivct.insert(ivct.end(), iv.begin(), iv.end());
    ivct.insert(ivct.end(), ct.begin(), ct.end());

    std::vector<uint8_t> mac(32);
    unsigned int macLen = 32;
    HMAC(EVP_sha256(),
        macKey.data(), macKey.size(),
        ivct.data(), ivct.size(),
        mac.data(), &macLen);

    return cipherString(2, b64Encode(iv), b64Encode(ct), b64Encode(mac));
}