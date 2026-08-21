#include <catch2/catch_test_macros.hpp>
#include <iostream>
#include "VaultCrypto/VaultCrypto.h"

/*
 * TODO: Don't Use B64 Encode or Decode
 * TODO: Test invalid tests
*/

/*
 * Encrypting will produce a different result everytime
*/
TEST_CASE("Encrypt/Decrypt Test") {
    ClientWarden::VaultCrypto crypto(true);

    Botan::secure_vector<uint8_t> encKey = 
        ClientWarden::b64Decode("GNuySg6B8dB8TPuz7z9kBDbn60iUKGT/P2pVUO9h4dM=");
    Botan::secure_vector<uint8_t> macKey = 
        ClientWarden::b64Decode("yZzs3Z5PrweGEbRqw63hEo4NTbhpEAlfAHHcPYRjVgI=");

    std::cout << ClientWarden::b64Encode(encKey) << std::endl;
    std::cout << ClientWarden::b64Encode(macKey) << std::endl;

    Botan::secure_vector<uint8_t> og = {
        'C', 'l', 'i', 'e', 'n', 't', 'W', 'a', 'r', 'd', 'e', 'n'
    };

    std::string enc = crypto.Encrypt(og, encKey, macKey);
    Botan::secure_vector<uint8_t> dec = crypto.Decrypt(enc, encKey, macKey);

    REQUIRE(dec == og);
}

TEST_CASE("EncryptAsStr/Decrypt Test") {
    ClientWarden::VaultCrypto crypto(true);

    Botan::secure_vector<uint8_t> encKey = 
        ClientWarden::b64Decode("ehsn1qxSFaQovtMm66SxFtaOFfg52hLUXnLQCr9Ljok=");
    Botan::secure_vector<uint8_t> macKey = 
        ClientWarden::b64Decode("WN6DIjan7ZT49aVtx+UOx6GCqcX5Dzvxrk88mbhQFFo=");

    Botan::secure_vector<uint8_t> og = {
        'C', 'l', 'i', 'e', 'n', 't', 'W', 'a', 'r', 'd', 'e', 'n'
    };

    std::string enc = crypto.Encrypt("ClientWarden", encKey, macKey);
    Botan::secure_vector<uint8_t> dec = crypto.Decrypt(enc, encKey, macKey);

    REQUIRE(dec == og);
}

TEST_CASE("EncryptRaw/DecryptRaw Test") {
    ClientWarden::VaultCrypto crypto(true);

    Botan::secure_vector<uint8_t> encKey = 
        ClientWarden::b64Decode("12s2bfR9+dFPzeapUdqr16+zSaZ5nP+A9bGC9Mol/sA=");
    Botan::secure_vector<uint8_t> macKey = 
        ClientWarden::b64Decode("glVSA/tpRK5pe/FswgJdHk+y8QQ3LlOeYgMj09rdmaQ=");

    Botan::secure_vector<uint8_t> og = {
        'C', 'l', 'i', 'e', 'n', 't', 'W', 'a', 'r', 'd', 'e', 'n'
    };

    std::string enc = crypto.EncryptRaw(og, encKey, macKey);

    Botan::secure_vector<uint8_t> v_enc(enc.begin(), enc.end());

    std::string dec = crypto.DecryptRaw(v_enc, encKey, macKey);

    REQUIRE(dec == "ClientWarden");
}

TEST_CASE("Decrypt Test") {
    ClientWarden::VaultCrypto crypto(true);

    /*
     * Had to hardcode these since I need to use them later
    */
    Botan::secure_vector<uint8_t> encKey = ClientWarden::b64Decode("HkpT6z8HAIrdUjMlMBcPDprnYFe4e6Lfius7YhNmCkY=");
    Botan::secure_vector<uint8_t> macKey = ClientWarden::b64Decode("AtHPCgB/SlDnlEf9WA0JMtl63oDkLpVnPCZJlyOL01s=");

    Botan::secure_vector<uint8_t> actualValue = {
        'T', 'e', 'p'
    };

    Botan::secure_vector<uint8_t> dec = crypto.Decrypt(
        "2.mnIBpndY7sS+DSZQDSKsMA==|OdC0I2BW6Po3UdfDFGTJ+Q==|aDj5gC/9iM5/AwjJmBUCSoE185XDREZM69XGGNV2iog=", encKey, macKey);

    REQUIRE(dec == actualValue);
}

TEST_CASE("Decrypt As String Test") {
    ClientWarden::VaultCrypto crypto(true);

    /*
     * Had to hardcode these since I need to use them later
    */
    Botan::secure_vector<uint8_t> encKey = ClientWarden::b64Decode("HkpT6z8HAIrdUjMlMBcPDprnYFe4e6Lfius7YhNmCkY=");
    Botan::secure_vector<uint8_t> macKey = ClientWarden::b64Decode("AtHPCgB/SlDnlEf9WA0JMtl63oDkLpVnPCZJlyOL01s=");

    std::string dec = crypto.DecryptAsStr(
        "2.mnIBpndY7sS+DSZQDSKsMA==|OdC0I2BW6Po3UdfDFGTJ+Q==|aDj5gC/9iM5/AwjJmBUCSoE185XDREZM69XGGNV2iog=", encKey, macKey);

    REQUIRE(dec == "Tep");
}

TEST_CASE("DecryptRaw Test") {
    ClientWarden::VaultCrypto crypto(true);
    
    Botan::secure_vector<uint8_t> encKey = ClientWarden::b64Decode("Ay1c+hUhNSwVi9XkYg+WDEG6wV4IvfYA0juwbBrptKA=");
    Botan::secure_vector<uint8_t> macKey = ClientWarden::b64Decode("4xkE6NUAROZOl6LhnVHdBh7ydAX4RkxDRAIuuRK86tw=");

    std::string dec = crypto.DecryptRaw(ClientWarden::b64Decode("AmKtjLq1L7nHSI9mNmdAJMDQ7Gsp21otZstoMlYUrwHBV2eVleasB3JEThlMT3oqgNM6P/tDsLwSflWF6lig1PY="), encKey, macKey);

    REQUIRE(dec == "ClientWarden");
}

TEST_CASE("Cipher String (1)") {
    ClientWarden::VaultCrypto crypto(true);

    std::string iv = "mnIBpndY7sS+DSZQDSKsMA==";
    std::string ct = "OdC0I2BW6Po3UdfDFGTJ+Q==";
    std::string mac = "aDj5gC/9iM5/AwjJmBUCSoE185XDREZM69XGGNV2iog=";

    std::string result = crypto.cipherString(2, iv, ct, mac);

    REQUIRE(result == "2.mnIBpndY7sS+DSZQDSKsMA==|OdC0I2BW6Po3UdfDFGTJ+Q==|aDj5gC/9iM5/AwjJmBUCSoE185XDREZM69XGGNV2iog=");
}

TEST_CASE("Cipher String (2)") {
    ClientWarden::VaultCrypto crypto(true);

    std::string iv = "mnIBpndY7sS+DSZQDSKsMA==";
    std::string ct = "OdC0I2BW6Po3UdfDFGTJ+Q==";
    std::string mac = "";

    std::string result = crypto.cipherString(2, iv, ct, mac);

    REQUIRE(result == "2.mnIBpndY7sS+DSZQDSKsMA==|OdC0I2BW6Po3UdfDFGTJ+Q==");
}

TEST_CASE("Make Key (600 000)") {
    ClientWarden::VaultCrypto crypto(true);

    std::string password = "Cl1entW@rden!2345";
    std::string salt = "cwuser@ct5.app";

    Botan::secure_vector<uint8_t> result = crypto.makeKey(password, salt, 600000);

    REQUIRE(ClientWarden::b64Encode(result) == "ZpUXcWr1drwwXyagHbbYKjkU/jAR6e2MlvAo8WoWmGY=");
}

TEST_CASE("Make Key (6 000 000)") {
    ClientWarden::VaultCrypto crypto(true);

    std::string password = "Cl1entW@rden!2345";
    std::string salt = "cwuser@ct5.app";

    Botan::secure_vector<uint8_t> result = crypto.makeKey(password, salt, 6000000);

    REQUIRE(ClientWarden::b64Encode(result) == "jIYLWmvcnFcr3+WwlsyJtGGoAvd2rrtOG2v5EOoA1C4=");
}

TEST_CASE("HashedPassword Test") {
    ClientWarden::VaultCrypto crypto(true);

    std::string password = "Cl1entW@rden!2345";

    std::string result = crypto.hashedPassword(password, ClientWarden::b64Decode("jIYLWmvcnFcr3+WwlsyJtGGoAvd2rrtOG2v5EOoA1C4="));

    REQUIRE(result == "aBGZrGGJeaxdM4b5D1SPltKeq7levslhTkm1baSmfrk=");
}

TEST_CASE("Macs Equal Test") {
    ClientWarden::VaultCrypto crypto(true);

    Botan::secure_vector<uint8_t> macKey(32, 0x1);
    Botan::secure_vector<uint8_t> mac1 = {
        0xaa, 0xbb, 0xcc, 0xdd
    };
    Botan::secure_vector<uint8_t> mac2 = {
        0xaa, 0xbb, 0xcc, 0xdd
    };

    REQUIRE(crypto.macsEqual(macKey, mac1, mac2));
}

/*
 * We can use the same key for enc and mac keys
 * bc we won't be using them.
*/
TEST_CASE("HKDF Stretch Test") {
    std::shared_ptr<Botan::secure_vector<uint8_t>> key = 
        std::make_shared<Botan::secure_vector<uint8_t>>(
            ClientWarden::b64Decode("jIYLWmvcnFcr3+WwlsyJtGGoAvd2rrtOG2v5EOoA1C4="));

    ClientWarden::VaultCrypto crypto(key, key, key);

    std::string info = "KeyClientWarden";

    Botan::secure_vector<uint8_t> res1 = crypto.hkdfStretch(info);
    Botan::secure_vector<uint8_t> res2 = crypto.hkdfStretch(info);

    REQUIRE(res1 == res2);
}

TEST_CASE("URI Checksum/DecryptAsStr Test") {
    ClientWarden::VaultCrypto crypto(true);

    Botan::secure_vector<uint8_t> encKey = 
        ClientWarden::b64Decode("12s2bfR9+dFPzeapUdqr16+zSaZ5nP+A9bGC9Mol/sA=");
    Botan::secure_vector<uint8_t> macKey = 
        ClientWarden::b64Decode("glVSA/tpRK5pe/FswgJdHk+y8QQ3LlOeYgMj09rdmaQ=");
    
    std::string url = "https://example.com";

    std::string chksum = crypto.getUriChecksum(url, encKey, macKey);
    std::string result = crypto.DecryptAsStr(chksum, encKey, macKey);

    REQUIRE(result == "EAaArVRs5qV39C9S3zO0z9ynVoWeZkuNfeMpsVDQnOk=");
}