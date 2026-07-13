#pragma once
#include <string>
#include <algorithm>
#include <botan/secmem.h>
#include <botan/mem_ops.h>
#include <openssl/kdf.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include "Clientwarden.h"
#include "VaultUtils/VaultUtils.h"

namespace ClientWarden {
    /*
     * Only stores cryptography funcs
    */
    class VaultCrypto {
    public:
        VaultCrypto(std::shared_ptr<Botan::secure_vector<uint8_t>> encKey, std::shared_ptr<Botan::secure_vector<uint8_t>> macKey,
            std::shared_ptr<Botan::secure_vector<uint8_t>> internalKey);

        std::pair<Botan::secure_vector<uint8_t>, Botan::secure_vector<uint8_t>> getEncMacKey(std::string protectedKey);

        Botan::secure_vector<uint8_t> makeKey(const std::string& password, const std::string& salt, int iterations);
        std::string cipherString(int encryptionType, const std::string& iv, const std::string& ct, const std::string& mac);
        std::string makeEncKey(const Botan::secure_vector<uint8_t>& key);
        std::string hashedPassword(const std::string& password, const Botan::secure_vector<uint8_t>& key);

        bool macsEqual(const Botan::secure_vector<uint8_t>& macKey, const Botan::secure_vector<uint8_t>& mac1, const Botan::secure_vector<uint8_t>& mac2);

        Botan::secure_vector<uint8_t> Decrypt(const std::string& str, const Botan::secure_vector<uint8_t>& key, const Botan::secure_vector<uint8_t>& macKey);
        std::string DecryptAsStr(const std::string& str, const Botan::secure_vector<uint8_t>& itemEncKey, const Botan::secure_vector<uint8_t>& itemMacKey);
        std::string Encrypt(const Botan::secure_vector<uint8_t>& pt, const Botan::secure_vector<uint8_t>& key, const Botan::secure_vector<uint8_t>& macKey);
        std::string Encrypt(std::string str, const Botan::secure_vector<uint8_t>& key, const Botan::secure_vector<uint8_t>& macKey);

        std::string EncryptRaw(const Botan::secure_vector<uint8_t>& pt, const Botan::secure_vector<uint8_t>& key, const Botan::secure_vector<uint8_t>& macKey);
        std::string DecryptRaw(const Botan::secure_vector<uint8_t>& pt, const Botan::secure_vector<uint8_t>& key, const Botan::secure_vector<uint8_t>& macKey);

        Botan::secure_vector<uint8_t> hkdfStretch(const std::string& info);
        std::pair<Botan::secure_vector<uint8_t>, Botan::secure_vector<uint8_t>> generateEncMacKeys();

        std::string getUriChecksum(std::string& uri, Botan::secure_vector<uint8_t> itemEncKey, Botan::secure_vector<uint8_t> itemMacKey);

        std::pair<Botan::secure_vector<uint8_t>, Botan::secure_vector<uint8_t>> splitKeys(std::string mainKey);
    private:
        std::shared_ptr<Botan::secure_vector<uint8_t>> encKey;
        std::shared_ptr<Botan::secure_vector<uint8_t>> macKey;
        std::shared_ptr<Botan::secure_vector<uint8_t>> internalKey;
    };
}