#include "Vault.h"

namespace ClientWarden::Vault {
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
            return std::vector<uint8_t>();
        }

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            spdlog::error("failed to create cipher context");
            return std::vector<uint8_t>();
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
            return "";
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

    void Vault::getMainKeys() {
        std::string protectedKey = vaultData["profile"]["key"];

        std::vector<uint8_t> stretchedEncKey = hkdfStretch("enc");
        std::vector<uint8_t> stretchedMacKey = hkdfStretch("mac");

        std::vector<uint8_t> decryptedProtectedKey = InternalDecrypt(protectedKey, stretchedEncKey, stretchedMacKey);

        encKey = std::vector<uint8_t>(decryptedProtectedKey.begin(), decryptedProtectedKey.begin() + 32);
        macKey = std::vector<uint8_t>(decryptedProtectedKey.begin() + 32, decryptedProtectedKey.end());

        OPENSSL_cleanse(decryptedProtectedKey.data(), decryptedProtectedKey.size());
    }

    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> Vault::getKeysFromCipher(std::string mainKey) {
        std::vector<uint8_t> itemKey = InternalDecrypt(mainKey, encKey, macKey);

        std::vector<uint8_t> itemEncKey(itemKey.begin(), itemKey.begin() + 32);
        std::vector<uint8_t> itemMacKey(itemKey.begin() + 32, itemKey.end());

        OPENSSL_cleanse(itemKey.data(), itemKey.size());

        return { itemEncKey, itemMacKey };
    }

    std::vector<uint8_t> Vault::hkdfStretch(const std::string& info) {
        std::vector<uint8_t> data(info.begin(), info.end());
        data.push_back(0x01);

        std::vector<uint8_t> out(32);
        unsigned int len = 32;

        HMAC(EVP_sha256(),
            internalKey.data(), internalKey.size(),
            data.data(), data.size(),
            out.data(), &len);
            
        return out;
    }

    std::string Vault::decryptItem(std::string item, std::vector<uint8_t> itemEncKey, std::vector<uint8_t> itemMacKey) {
        std::vector<uint8_t> decItemRaw = InternalDecrypt(item, itemEncKey, itemMacKey);

        std::string decItem(decItemRaw.begin(), decItemRaw.end());

        OPENSSL_cleanse(decItemRaw.data(), decItemRaw.size());

        return decItem;
    }

    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> Vault::generateEncMacKeys() {
        std::vector<uint8_t> itemEncKey(32);
        std::vector<uint8_t> itemMacKey(32);

        if (!RAND_bytes(itemEncKey.data(), 32)) {
            spdlog::info("Failed to generate encKey");
            return { itemEncKey, itemMacKey };
        }
        if (!RAND_bytes(itemMacKey.data(), 32)) {
            spdlog::info("Failed to generate macKey");
            return { itemEncKey, itemMacKey };
        }

        return { itemEncKey, itemMacKey };
    }

    std::string Vault::getUriChecksum(std::string& uri, std::vector<uint8_t> itemEncKey, std::vector<uint8_t> itemMacKey) {
        std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
        SHA256(
            reinterpret_cast<const uint8_t*>(uri.data()),
            uri.size(),
            hash.data()
        );

        return Encrypt(b64Encode(hash), itemEncKey, itemMacKey);
    }

    std::string Vault::Encrypt(std::string str, const std::vector<uint8_t>& itemEncKey, const std::vector<uint8_t>& itemMacKey) {
        std::vector<uint8_t> item(str.begin(), str.end());
        std::string enc = InternalEncrypt(item, itemEncKey, itemMacKey);
        OPENSSL_cleanse(item.data(), item.size());

        return enc;
    }

    std::string Vault::Decrypt(std::string str, const std::vector<uint8_t>& itemEncKey, const std::vector<uint8_t>& itemMacKey) {
        std::vector<uint8_t> dec = InternalDecrypt(str, itemEncKey, itemMacKey);
        std::string decStr(dec.begin(), dec.end());
        OPENSSL_cleanse(dec.data(), dec.size());

        return decStr;
    }
}