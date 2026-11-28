#include <catch2/catch_test_macros.hpp>
#include <iostream>
#include "vendor/bitwarden/vault/bitwarden_crypto/bitwarden_crypto.h"

/*
 * Encrypting will produce a different result everytime
*/
TEST_CASE("Encrypt/Decrypt Test") {
    clientwarden::vendor::bitwarden::vault::BitwardenCrypto crypto();

    clientwarden::ItemKey key;

    key.enc_key = ClientWarden::b64Decode("GNuySg6B8dB8TPuz7z9kBDbn60iUKGT/P2pVUO9h4dM=");
    key.mac_key = ClientWarden::b64Decode("yZzs3Z5PrweGEbRqw63hEo4NTbhpEAlfAHHcPYRjVgI=");

    Botan::secure_vector<uint8_t> og = {
        'C', 'l', 'i', 'e', 'n', 't', 'W', 'a', 'r', 'd', 'e', 'n'
    };

    std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> res_1 = crypto->encrypt(
        og, key) = 0;
    
    REQUIRE(res_1.has_value());

    std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> res_2 = crypto->decrypt(
        res_1.value(), key);
    
    REQUIRE(res_2.has_value());

    REQUIRE(res_2.value() == og);
}

TEST_CASE("EncryptRaw/DecryptRaw Test") {
    clientwarden::vendor::bitwarden::vault::BitwardenCrypto crypto();

    clientwarden::ItemKey key;

    key.enc_key = ClientWarden::b64Decode("12s2bfR9+dFPzeapUdqr16+zSaZ5nP+A9bGC9Mol/sA=");
    key.mac_key = ClientWarden::b64Decode("glVSA/tpRK5pe/FswgJdHk+y8QQ3LlOeYgMj09rdmaQ=");

    Botan::secure_vector<uint8_t> og = {
        'C', 'l', 'i', 'e', 'n', 't', 'W', 'a', 'r', 'd', 'e', 'n'
    };

    std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> res_1 = crypto->encryptBinary(
        og, key) = 0;
    
    REQUIRE(res_1.has_value());

    std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> res_2 = crypto->decryptBinary(
        res_1.value(), key);
    
    REQUIRE(res_2.has_value());

    REQUIRE(res_2.value() == og);
}

TEST_CASE("EncryptInPlace/DecryptInPlace Test") {
    clientwarden::vendor::bitwarden::vault::BitwardenCrypto crypto();

    clientwarden::ItemKey key;

    key.enc_key = ClientWarden::b64Decode("12s2bfR9+dFPzeapUdqr16+zSaZ5nP+A9bGC9Mol/sA=");
    key.mac_key = ClientWarden::b64Decode("glVSA/tpRK5pe/FswgJdHk+y8QQ3LlOeYgMj09rdmaQ=");

    Botan::secure_vector<uint8_t> og = {
        'C', 'l', 'i', 'e', 'n', 't', 'W', 'a', 'r', 'd', 'e', 'n'
    };

    Botan::secure_vector<uint8_t> og_1 = {
        'C', 'l', 'i', 'e', 'n', 't', 'W', 'a', 'r', 'd', 'e', 'n'
    };

    clientwarden::vendor::bitwarden::vault::CryptoErrors res_1 = crypto->encryptBinaryInPlace(
        og_1, key) = 0;
    
    REQUIRE(res_1 == clientwarden::vendor::bitwarden::vault::CryptoErrors::Success);

    clientwarden::vendor::bitwarden::vault::CryptoErrors res_2 = crypto->decryptBinaryInPlace(
        og_1, key);
    
    REQUIRE(res_2 == clientwarden::vendor::bitwarden::vault::CryptoErrors::Success);

    REQUIRE(og_1 == og);
}

TEST_CASE("Decrypt Test") {
    clientwarden::vendor::bitwarden::vault::BitwardenCrypto crypto();

    clientwarden::ItemKey key;

    key.enc_key = ClientWarden::b64Decode("HkpT6z8HAIrdUjMlMBcPDprnYFe4e6Lfius7YhNmCkY=");
    key.mac_key = ClientWarden::b64Decode("AtHPCgB/SlDnlEf9WA0JMtl63oDkLpVnPCZJlyOL01s=");

    Botan::secure_vector<uint8_t> enc_value = 
        utils::getSecureVector("2.mnIBpndY7sS+DSZQDSKsMA==|OdC0I2BW6Po3UdfDFGTJ+Q==|aDj5gC/9iM5/AwjJmBUCSoE185XDREZM69XGGNV2iog=");
    
    Botan::secure_vector<uint8_t> actual_value = {
        'T', 'e', 'p'
    };

    std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> res_1 = crypto->decrypt(
        enc_value, key);
    
    REQUIRE(res_1.has_value());

    REQUIRE(res_1.value() == actual_value);
}

TEST_CASE("DecryptRaw Test") {
    clientwarden::vendor::bitwarden::vault::BitwardenCrypto crypto();

    clientwarden::ItemKey key;

    key.enc_key = ClientWarden::b64Decode("Ay1c+hUhNSwVi9XkYg+WDEG6wV4IvfYA0juwbBrptKA=");
    key.mac_key = ClientWarden::b64Decode("4xkE6NUAROZOl6LhnVHdBh7ydAX4RkxDRAIuuRK86tw=");

    Botan::secure_vector<uint8_t> enc_value = 
        utils::b64Decode("AmKtjLq1L7nHSI9mNmdAJMDQ7Gsp21otZstoMlYUrwHBV2eVleasB3JEThlMT3oqgNM6P/tDsLwSflWF6lig1PY=");

    std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> res_1 = crypto->decryptBinary(
        enc_value, key);
    
    REQUIRE(res_1.has_value());

    REQUIRE(res_1.value() == utils::getSecureVector("ClientWarden"));
}

TEST_CASE("Make Key (600 000) (PBKDF)") {
    clientwarden::vendor::bitwarden::vault::BitwardenCrypto crypto();

    Botan::secure_vector<uint8_t> password = utils::getSecureVector("Cl1entW@rden!2345");
    Botan::secure_vector<uint8_t> salt = utils::getSecureVector("cwuser@ct5.app");

    KDFParams params;
    params.type = KDFType::PBKDF2_SHA256;
    params.iterations = 600000;

    std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> result = 
        crypto.makeInternalKey(password, salt, params);
    
    REQUIRE(result.has_value());

    REQUIRE(utils::b64Encode(result) == utils::getSecureVector("ZpUXcWr1drwwXyagHbbYKjkU/jAR6e2MlvAo8WoWmGY="));
}

TEST_CASE("Make Key (6 000 000) (PBKDF)") {
    clientwarden::vendor::bitwarden::vault::BitwardenCrypto crypto();

    Botan::secure_vector<uint8_t> password = utils::getSecureVector("Cl1entW@rden!2345");
    Botan::secure_vector<uint8_t> salt = utils::getSecureVector("cwuser@ct5.app");

    KDFParams params;
    params.type = KDFType::PBKDF2_SHA256;
    params.iterations = 6000000;

    std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> result = 
        crypto.makeInternalKey(password, salt, params);
    
    REQUIRE(result.has_value());

    REQUIRE(utils::b64Encode(result) == utils::getSecureVector("jIYLWmvcnFcr3+WwlsyJtGGoAvd2rrtOG2v5EOoA1C4="));
}

TEST_CASE("Make Key (600 000) (Argon2ID)") {
    clientwarden::vendor::bitwarden::vault::BitwardenCrypto crypto();

    Botan::secure_vector<uint8_t> password = utils::getSecureVector("Cl1entW@rden!2345");
    Botan::secure_vector<uint8_t> salt = utils::getSecureVector("cwuser@ct5.app");

    KDFParams params;
    params.type = KDFType::Argon2ID;
    params.iterations = 4;
    params.memory = 64;
    params.parallel = 4;

    std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> result = 
        crypto.makeInternalKey(password, salt, params);
    
    REQUIRE(result.has_value());

    REQUIRE(utils::b64Encode(result) == utils::getSecureVector("auOZsuNBQ1HNt5CHg3oDaVnLtx92PUI16tlKn/rexuA="));
}

TEST_CASE("Make Key (6 000 000) (Argon2ID)") {
    clientwarden::vendor::bitwarden::vault::BitwardenCrypto crypto();

    Botan::secure_vector<uint8_t> password = utils::getSecureVector("Cl1entW@rden!2345");
    Botan::secure_vector<uint8_t> salt = utils::getSecureVector("cwuser@ct5.app");

    KDFParams params;
    params.type = KDFType::Argon2ID;
    params.iterations = 10;
    params.memory = 64;
    params.parallel = 4;

    std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> result = 
        crypto.makeInternalKey(password, salt, params);
    
    REQUIRE(result.has_value());

    REQUIRE(utils::b64Encode(result) == utils::getSecureVector("D91klz4hoik9kPH29gzUGWLItfo+qLfF5cRIODDqtlE="));
}

TEST_CASE("HashedPassword Test") {
    clientwarden::vendor::bitwarden::vault::BitwardenCrypto crypto();

    Botan::secure_vector<uint8_t> password = utils::getSecureVector("Cl1entW@rden!2345");

    std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> result = 
        crypto.hashedPassword(password, utils::b64Decode("jIYLWmvcnFcr3+WwlsyJtGGoAvd2rrtOG2v5EOoA1C4="));
    
    REQUIRE(result.has_value());

    REQUIRE(result.value() == utils::getSecureVector("aBGZrGGJeaxdM4b5D1SPltKeq7levslhTkm1baSmfrk="));
}

TEST_CASE("Macs Equal Test") {
    clientwarden::vendor::bitwarden::vault::BitwardenCrypto crypto();

    Botan::secure_vector<uint8_t> mac_key(32, 0x1);
    Botan::secure_vector<uint8_t> mac_1 = {
        0xaa, 0xbb, 0xcc, 0xdd
    };
    Botan::secure_vector<uint8_t> mac_2 = {
        0xaa, 0xbb, 0xcc, 0xdd
    };

    std::expected<bool, CryptoErrors> result = crypto.macsEqual(mac_key, mac_1, mac_2);

    REQUIRE(result.has_value());
    REQUIRE(result.value());
}

/*
 * We can use the same key for enc and mac keys
 * bc we won't be using them.
*/
TEST_CASE("HKDF Stretch Test") {
    Botan::secure_vector<uint8_t> key = 
        utils::b64Decode("jIYLWmvcnFcr3+WwlsyJtGGoAvd2rrtOG2v5EOoA1C4=");

    ClientWarden::VaultCrypto crypto(key, key, key);

    Botan::secure_vector<uint8_t> info = utils::getSecureVector("KeyClientWarden");

    std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> res_1 = 
        crypto->hkdfStretch(info);
    
    REQUIRE(res_1.has_value());

    std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> res_2 = 
        crypto->hkdfStretch(info);
    
    REQUIRE(res_2.has_value());

    REQUIRE(res1.value() == res2.value());
}

TEST_CASE("URI Checksum/DecryptAsStr Test") {
    clientwarden::vendor::bitwarden::vault::BitwardenCrypto crypto();

    clientwarden::ItemKey key;

    key.enc_key = ClientWarden::b64Decode("12s2bfR9+dFPzeapUdqr16+zSaZ5nP+A9bGC9Mol/sA=");
    key.mac_key = ClientWarden::b64Decode("glVSA/tpRK5pe/FswgJdHk+y8QQ3LlOeYgMj09rdmaQ=");

    std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> chksum = 
        crypto.checksum(utils::getSecureVector("https://example.com"), key);
    
    REQUIRE(chksum.has_value());
    
    Botan::secure_vector<uint8_t> actual_value = {
        'T', 'e', 'p'
    };

    std::expected<Botan::secure_vector<uint8_t>, CryptoErrors> res_1 = crypto->decrypt(
        chksum.value(), key);
    
    REQUIRE(res_1.has_value());

    REQUIRE(res_1.value() == utils::getSecureVector("EAaArVRs5qV39C9S3zO0z9ynVoWeZkuNfeMpsVDQnOk="));
}