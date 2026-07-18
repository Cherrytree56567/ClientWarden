#include "VaultCrypto.h"

namespace ClientWarden {
    VaultCrypto::VaultCrypto(std::shared_ptr<Botan::secure_vector<uint8_t>> encKey, std::shared_ptr<Botan::secure_vector<uint8_t>> macKey,
        std::shared_ptr<Botan::secure_vector<uint8_t>> internalKey) :
        encKey(encKey), macKey(macKey), internalKey(internalKey) {
        
    }

    std::pair<Botan::secure_vector<uint8_t>, Botan::secure_vector<uint8_t>> VaultCrypto::getEncMacKey(std::string protectedKey) {
        Botan::secure_vector<uint8_t> itemKey = Decrypt(protectedKey, *encKey, *macKey);

        Botan::secure_vector<uint8_t> itemEncKey(itemKey.begin(), itemKey.begin() + 32);
        Botan::secure_vector<uint8_t> itemMacKey(itemKey.begin() + 32, itemKey.end());

        Botan::secure_scrub_memory(itemKey.data(), itemKey.size());

        return { std::move(itemEncKey), std::move(itemMacKey) };
    }

    std::pair<Botan::secure_vector<uint8_t>, Botan::secure_vector<uint8_t>> VaultCrypto::getEncMacKey(std::string protectedKey, 
        Botan::secure_vector<uint8_t> dec_itemEncKey, Botan::secure_vector<uint8_t> dec_itemMacKey) {
        Botan::secure_vector<uint8_t> itemKey = Decrypt(protectedKey, dec_itemEncKey, dec_itemMacKey);

        Botan::secure_vector<uint8_t> itemEncKey(itemKey.begin(), itemKey.begin() + 32);
        Botan::secure_vector<uint8_t> itemMacKey(itemKey.begin() + 32, itemKey.end());

        Botan::secure_scrub_memory(itemKey.data(), itemKey.size());

        return { std::move(itemEncKey), std::move(itemMacKey) };
    }

    Botan::secure_vector<uint8_t> VaultCrypto::makeKey(const std::string& password, const std::string& salt, int iterations) {
        Botan::secure_vector<uint8_t> key(256 / 8);

        int result = PKCS5_PBKDF2_HMAC(
            password.c_str(), password.size(),
            reinterpret_cast<const uint8_t*>(salt.data()), salt.size(),
            iterations,
            EVP_sha256(),
            key.size(), key.data()
        );

        if (result != 1) {
            logger->error("makeKey : PBKDF2 failed");
            throw std::runtime_error("PBKDF2 failed");
        }

        return key;
    }

    std::string VaultCrypto::cipherString(int encryptionType, const std::string& iv, const std::string& ct, const std::string& mac) {
        std::string result = std::to_string(encryptionType) + "." + iv + "|" + ct;

        if (!mac.empty()) {
            result += "|" + mac;
        }

        return result;
    }

    std::string VaultCrypto::makeEncKey(const Botan::secure_vector<uint8_t>& key) {
        /*
         * pt[0, 32] becomes the cipher encryption key
         * pt[32, 32] becomes the mac key
         */
        Botan::secure_vector<uint8_t> pt(64);
        Botan::secure_vector<uint8_t> iv(16);

        RAND_bytes(pt.data(), pt.size());
        RAND_bytes(iv.data(), iv.size());

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            logger->error("Failed to create cipher context");
            throw std::runtime_error("Failed to create cipher context");
        }

        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data());

        Botan::secure_vector<uint8_t> ct(pt.size() + 16);

        int len = 0;
        int ct_len = 0;

        EVP_EncryptUpdate(ctx, ct.data(), &len, pt.data(), pt.size());
        ct_len += len;

        EVP_EncryptFinal_ex(ctx, ct.data() + ct_len, &len);
        ct_len += len;

        ct.resize(ct_len);
        EVP_CIPHER_CTX_free(ctx);

        Botan::secure_scrub_memory(pt.data(), pt.size());
        
        std::string cipEncKey = cipherString(0, b64Encode(iv), b64Encode(ct), "");

        Botan::secure_scrub_memory(iv.data(), iv.size());
        Botan::secure_scrub_memory(ct.data(), ct.size());

        return cipEncKey;
    }

    /*
     * base64-encode a wrapped, stretched password+salt for signup/login
     */
    std::string VaultCrypto::hashedPassword(const std::string& password, const Botan::secure_vector<uint8_t>& key) {
        Botan::secure_vector<uint8_t> hashed(256 / 8);
        PKCS5_PBKDF2_HMAC(
            reinterpret_cast<const char*>(key.data()), key.size(),
            reinterpret_cast<const uint8_t*>(password.data()), password.size(),
            1,
            EVP_sha256(),
            hashed.size(), hashed.data()
        );

        std::string hashedPass = b64Encode(hashed);

        Botan::secure_scrub_memory(hashed.data(), hashed.size());

        return hashedPass;
    }

    /*
     * compare two hmacs, with double hmac verification
     * https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2011/february/double-hmac-verification/
     */
    bool VaultCrypto::macsEqual(const Botan::secure_vector<uint8_t>& macKey, const Botan::secure_vector<uint8_t>& mac1, 
        const Botan::secure_vector<uint8_t>& mac2) {
        Botan::secure_vector<uint8_t> hmac1(32);
        Botan::secure_vector<uint8_t> hmac2(32);
        unsigned int len = 32;

        HMAC(EVP_sha256(),
            macKey.data(), macKey.size(),
            mac1.data(), mac1.size(),
            hmac1.data(), &len);

        HMAC(EVP_sha256(),
            macKey.data(), macKey.size(),
            mac2.data(), mac2.size(),
            hmac2.data(), &len);
        
        bool macCheck = CRYPTO_memcmp(hmac1.data(), hmac2.data(), 32) == 0;

        Botan::secure_scrub_memory(hmac1.data(), hmac1.size());
        Botan::secure_scrub_memory(hmac2.data(), hmac2.size());

        return macCheck;
    }

    Botan::secure_vector<uint8_t> VaultCrypto::Decrypt(const std::string& str, const Botan::secure_vector<uint8_t>& key, 
        const Botan::secure_vector<uint8_t>& macKey) {
        if (str[0] != '2') {
            logger->error("Decryption Type {} Unimplemented", std::string(1, str[0]));
            throw std::runtime_error("Decryption Type " + std::string(1, str[0]) + " Unimplemented");
        }

        std::string rest = str.substr(2);

        std::vector<std::string> parts;
        std::string current;

        for (char c : rest) {
            if (c == '|' && (int)parts.size() < 2) {
                parts.push_back(current);
                current.clear();
            } else {
                current += c;
            }
        }
        parts.push_back(current);

        if (parts.size() != 3) {
            logger->error("invalid cipher string format");
            throw std::runtime_error("invalid cipher string format");
        }

        Botan::secure_vector<uint8_t> iv = b64Decode(parts[0]);
        Botan::secure_vector<uint8_t> ct = b64Decode(parts[1]);
        Botan::secure_vector<uint8_t> mac = b64Decode(parts[2]);

        parts.clear();

        Botan::secure_vector<uint8_t> ivct;
        ivct.insert(ivct.end(), iv.begin(), iv.end());
        ivct.insert(ivct.end(), ct.begin(), ct.end());

        Botan::secure_vector<uint8_t> cmac(32);
        unsigned int len = 32;
        HMAC(EVP_sha256(),
            macKey.data(), macKey.size(),
            ivct.data(), ivct.size(),
            cmac.data(), &len);

        if (!macsEqual(macKey, mac, cmac)) {
            logger->error("invalid mac");
            throw std::runtime_error("invalid mac");
        }

        Botan::secure_scrub_memory(ivct.data(), ivct.size());
        Botan::secure_scrub_memory(cmac.data(), cmac.size());

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            logger->error("failed to create cipher context");
            return Botan::secure_vector<uint8_t>();
        }

        EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data());

        Botan::secure_vector<uint8_t> pt(ct.size() + 16);
        int pt_len = 0;

        EVP_DecryptUpdate(ctx, pt.data(), reinterpret_cast<int*>(&len), ct.data(), ct.size());
        pt_len += len;

        if (EVP_DecryptFinal_ex(ctx, pt.data() + pt_len, (int*)&len) <= 0) {
            EVP_CIPHER_CTX_free(ctx);
            logger->error("invalid mac");
            throw std::runtime_error("invalid mac");
        }

        Botan::secure_scrub_memory(iv.data(), iv.size());
        Botan::secure_scrub_memory(ct.data(), ct.size());
        Botan::secure_scrub_memory(mac.data(), mac.size());
        
        pt_len += len;

        EVP_CIPHER_CTX_free(ctx);
        pt.resize(pt_len);
        return pt;
    }

    std::string VaultCrypto::DecryptAsStr(const std::string& str, const Botan::secure_vector<uint8_t>& itemEncKey, 
        const Botan::secure_vector<uint8_t>& itemMacKey) {
        Botan::secure_vector<uint8_t> decrypted = Decrypt(str, itemEncKey, itemMacKey);
        std::string decryptedStr(decrypted.begin(), decrypted.end());

        Botan::secure_scrub_memory(decrypted.data(), decrypted.size());

        return decryptedStr;
    }

    std::string VaultCrypto::Encrypt(const Botan::secure_vector<uint8_t>& pt, const Botan::secure_vector<uint8_t>& key, 
        const Botan::secure_vector<uint8_t>& macKey) {
        Botan::secure_vector<uint8_t> iv(16);
        RAND_bytes(iv.data(), iv.size());

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            logger->error("failed to create cipher context");
            throw std::runtime_error("failed to create cipher context");
        }

        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data());

        Botan::secure_vector<uint8_t> ct(pt.size() + 16);
        int len = 0;
        int ctLen = 0;

        EVP_EncryptUpdate(ctx, ct.data(), &len, pt.data(), pt.size());
        ctLen += len;

        EVP_EncryptFinal_ex(ctx, ct.data() + ctLen, &len);
        ctLen += len;

        ct.resize(ctLen);
        EVP_CIPHER_CTX_free(ctx);

        Botan::secure_vector<uint8_t> ivct;
        ivct.insert(ivct.end(), iv.begin(), iv.end());
        ivct.insert(ivct.end(), ct.begin(), ct.end());

        Botan::secure_vector<uint8_t> mac(32);
        unsigned int macLen = 32;
        HMAC(EVP_sha256(),
            macKey.data(), macKey.size(),
            ivct.data(), ivct.size(),
            mac.data(), &macLen);
        
        std::string encrypted = cipherString(2, b64Encode(iv), b64Encode(ct), b64Encode(mac));

        Botan::secure_scrub_memory(iv.data(), iv.size());
        Botan::secure_scrub_memory(ct.data(), ct.size());
        Botan::secure_scrub_memory(ivct.data(), ivct.size());
        Botan::secure_scrub_memory(mac.data(), mac.size());
        
        return encrypted;
    }

    std::string VaultCrypto::EncryptRaw(const Botan::secure_vector<uint8_t>& pt, const Botan::secure_vector<uint8_t>& key, const Botan::secure_vector<uint8_t>& macKey) {
        Botan::secure_vector<uint8_t> iv(16);
        RAND_bytes(iv.data(), iv.size());

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            logger->error("failed to create cipher context");
            throw std::runtime_error("failed to create cipher context");
        }

        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data());

        Botan::secure_vector<uint8_t> ct(pt.size() + 16);
        int len = 0, ct_len = 0;

        EVP_EncryptUpdate(ctx, ct.data(), &len, pt.data(), pt.size());
        ct_len += len;

        EVP_EncryptFinal_ex(ctx, ct.data() + ct_len, &len);
        ct_len += len;

        ct.resize(ct_len);
        EVP_CIPHER_CTX_free(ctx);

        Botan::secure_vector<uint8_t> ivct;
        ivct.insert(ivct.end(), iv.begin(), iv.end());
        ivct.insert(ivct.end(), ct.begin(), ct.end());

        Botan::secure_vector<uint8_t> mac(32);
        unsigned int macLen = 32;
        HMAC(EVP_sha256(),
            macKey.data(), macKey.size(),
            ivct.data(), ivct.size(),
            mac.data(), &macLen);

        std::string buf;
        buf.reserve(1 + 16 + 32 + ct.size());
        buf.push_back(0x02);
        buf.append(reinterpret_cast<const char*>(iv.data()), 16);
        buf.append(reinterpret_cast<const char*>(mac.data()), 32);
        buf.append(reinterpret_cast<const char*>(ct.data()), ct.size());

        Botan::secure_scrub_memory(iv.data(), iv.size());
        Botan::secure_scrub_memory(ct.data(), ct.size());
        Botan::secure_scrub_memory(ivct.data(), ivct.size());
        Botan::secure_scrub_memory(mac.data(), mac.size());

        return buf;
    }

    /*
     * Fix this func later
    */
    std::string VaultCrypto::DecryptRaw(const Botan::secure_vector<uint8_t>& pt, const Botan::secure_vector<uint8_t>& key, const Botan::secure_vector<uint8_t>& macKey) {
        const uint8_t* iv = pt.data() + 1;
        const uint8_t* mac = pt.data() + 17;
        const uint8_t* ct = pt.data() + 49;
        size_t ctLen = pt.size() - 49;

        Botan::secure_vector<uint8_t> ivct;
        ivct.insert(ivct.end(), iv, iv + 16);
        ivct.insert(ivct.end(), ct, ct + ctLen);

        Botan::secure_vector<uint8_t> expectedMac(32);

        unsigned int macLen = 32;

        HMAC(EVP_sha256(), macKey.data(), macKey.size(), ivct.data(), ivct.size(), expectedMac.data(), &macLen);

        if (CRYPTO_memcmp(mac, expectedMac.data(), 32) != 0) {
            logger->error("RAW Decryption HMAC verification failed");
            throw std::runtime_error("RAW Decryption HMAC verification failed");
        }

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv);

        Botan::secure_vector<uint8_t> plain(ctLen + 16);
        int outLen = 0;
        int finalLen = 0;

        EVP_DecryptUpdate(ctx, plain.data(), &outLen, ct, ctLen);
        EVP_DecryptFinal_ex(ctx, plain.data() + outLen, &finalLen);
        EVP_CIPHER_CTX_free(ctx);
        plain.resize(outLen + finalLen);

        std::string decryptedCont = std::string(plain.begin(), plain.end());

        Botan::secure_scrub_memory(ivct.data(), ivct.size());
        Botan::secure_scrub_memory(expectedMac.data(), expectedMac.size());
        Botan::secure_scrub_memory(plain.data(), plain.size());

        return decryptedCont;
    }

    Botan::secure_vector<uint8_t> VaultCrypto::hkdfStretch(const std::string& info) {
        Botan::secure_vector<uint8_t> data(info.begin(), info.end());
        data.push_back(0x01);

        Botan::secure_vector<uint8_t> out(32);
        unsigned int len = 32;

        HMAC(EVP_sha256(),
            internalKey->data(), internalKey->size(),
            data.data(), data.size(),
            out.data(), &len);
        
        Botan::secure_scrub_memory(data.data(), data.size());
            
        return std::move(out);
    }

    std::pair<Botan::secure_vector<uint8_t>, Botan::secure_vector<uint8_t>> VaultCrypto::generateEncMacKeys() {
        Botan::secure_vector<uint8_t> itemEncKey(32);
        Botan::secure_vector<uint8_t> itemMacKey(32);

        if (!RAND_bytes(itemEncKey.data(), 32)) {
            logger->info("Failed to generate encKey");
            throw std::runtime_error("Failed to generate encKey");
        }
        if (!RAND_bytes(itemMacKey.data(), 32)) {
            logger->info("Failed to generate macKey");
            throw std::runtime_error("Failed to generate macKey");
        }

        return { std::move(itemEncKey), std::move(itemMacKey) };
    }

    std::string VaultCrypto::getUriChecksum(std::string& uri, Botan::secure_vector<uint8_t> itemEncKey, 
                                            Botan::secure_vector<uint8_t> itemMacKey) {
        Botan::secure_vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
        SHA256(
            reinterpret_cast<const uint8_t*>(uri.data()),
            uri.size(),
            hash.data()
        );

        std::string b64hash = b64Encode(hash);

        Botan::secure_vector<uint8_t> vecHash(b64hash.begin(), b64hash.end());

        std::string checksum = Encrypt(vecHash, itemEncKey, itemMacKey);

        Botan::secure_scrub_memory(hash.data(), hash.size());
        Botan::secure_scrub_memory(vecHash.data(), vecHash.size());

        return checksum;
    }

    std::pair<Botan::secure_vector<uint8_t>, Botan::secure_vector<uint8_t>> VaultCrypto::splitKeys(std::string mainKey) {
        Botan::secure_vector<uint8_t> itemKey = Decrypt(mainKey, *encKey, *macKey);

        Botan::secure_vector<uint8_t> itemEncKey(itemKey.begin(), itemKey.begin() + 32);
        Botan::secure_vector<uint8_t> itemMacKey(itemKey.begin() + 32, itemKey.end());

        Botan::secure_scrub_memory(itemKey.data(), itemKey.size());

        return { std::move(itemEncKey), std::move(itemMacKey) };
    }

    std::string VaultCrypto::Encrypt(std::string str, const Botan::secure_vector<uint8_t>& key, const Botan::secure_vector<uint8_t>& itemMacKey) {
        Botan::secure_vector<uint8_t> item(str.begin(), str.end());
        std::string enc = Encrypt(item, key, itemMacKey);
        Botan::secure_scrub_memory(item.data(), item.size());

        return enc;
    }
}