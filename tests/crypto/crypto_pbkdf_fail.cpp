#include <catch2/catch_test_macros.hpp>
#include <iostream>
#include "VaultCrypto/VaultCrypto.h"

/*
 * Encrypting will produce a different result everytime
*/
TEST_CASE("Encrypt Test (fail)") {
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

    std::string enc1 = crypto.Encrypt(og, encKey, macKey);
    std::string enc2 = crypto.Encrypt(og, encKey, macKey);

    REQUIRE(enc1 != enc2);
}

TEST_CASE("EncryptAsStr Test (fail)") {
    ClientWarden::VaultCrypto crypto(true);

    Botan::secure_vector<uint8_t> encKey = 
        ClientWarden::b64Decode("ehsn1qxSFaQovtMm66SxFtaOFfg52hLUXnLQCr9Ljok=");
    Botan::secure_vector<uint8_t> macKey = 
        ClientWarden::b64Decode("WN6DIjan7ZT49aVtx+UOx6GCqcX5Dzvxrk88mbhQFFo=");

    std::string enc1 = crypto.Encrypt("ClientWarden", encKey, macKey);
    std::string enc2 = crypto.Encrypt("ClientWarden", encKey, macKey);

    REQUIRE(enc1 != enc2);
}

TEST_CASE("EncryptRaw Test (fail)") {
    ClientWarden::VaultCrypto crypto(true);

    Botan::secure_vector<uint8_t> encKey = 
        ClientWarden::b64Decode("12s2bfR9+dFPzeapUdqr16+zSaZ5nP+A9bGC9Mol/sA=");
    Botan::secure_vector<uint8_t> macKey = 
        ClientWarden::b64Decode("glVSA/tpRK5pe/FswgJdHk+y8QQ3LlOeYgMj09rdmaQ=");

    Botan::secure_vector<uint8_t> og = {
        'C', 'l', 'i', 'e', 'n', 't', 'W', 'a', 'r', 'd', 'e', 'n'
    };

    std::string enc1 = crypto.EncryptRaw(og, encKey, macKey);
    std::string enc2 = crypto.EncryptRaw(og, encKey, macKey);

    REQUIRE(enc1 != enc2);
}

TEST_CASE("Decrypt Test (1) (fail)") {
    ClientWarden::VaultCrypto crypto(true);

    /*
     * Wrong Mac Key
    */
    Botan::secure_vector<uint8_t> encKey = ClientWarden::b64Decode("HkpT6z8HAIrdUjMlMBcPDprnYFe4e6Lfius7YhNmCkY=");
    Botan::secure_vector<uint8_t> macKey = ClientWarden::b64Decode("BtHPCgB/SlDnlEf9WA0JMtl63oDkLpVnPCZJlyOL01s=");

    REQUIRE_THROWS(crypto.Decrypt(
        "2.mnIBpndY7sS+DSZQDSKsMA==|OdC0I2BW6Po3UdfDFGTJ+Q==|aDj5gC/9iM5/AwjJmBUCSoE185XDREZM69XGGNV2iog=", encKey, macKey));
}

TEST_CASE("Decrypt Test (2) (fail)") {
    ClientWarden::VaultCrypto crypto(true);
    Botan::secure_vector<uint8_t> encKey = ClientWarden::b64Decode("HkpT6z8HAIrdUjMlMBcPDprnYFe4e6Lfius7YhNmCkY=");
    Botan::secure_vector<uint8_t> macKey = ClientWarden::b64Decode("AtHPCgB/SlDnlEf9WA0JMtl63oDkLpVnPCZJlyOL01s=");

    /*
     * Invalid Decrypt String
    */
    REQUIRE_THROWS(crypto.Decrypt("2.bt==|Ocli+ent==|fi/xxx/mejJmBUCPLZV2iog=", encKey, macKey));
}

TEST_CASE("DecryptAsStr Test (1) (fail)") {
    ClientWarden::VaultCrypto crypto(true);

    /*
     * Wrong Mac Key
    */
    Botan::secure_vector<uint8_t> encKey = ClientWarden::b64Decode("HkpT6z8HAIrdUjMlMBcPDprnYFe4e6Lfius7YhNmCkY=");
    Botan::secure_vector<uint8_t> macKey = ClientWarden::b64Decode("BtHPCgB/SlDnlEf9WA0JMtl63oDkLpVnPCZJlyOL01s=");

    REQUIRE_THROWS(crypto.DecryptAsStr(
        "2.mnIBpndY7sS+DSZQDSKsMA==|OdC0I2BW6Po3UdfDFGTJ+Q==|aDj5gC/9iM5/AwjJmBUCSoE185XDREZM69XGGNV2iog=", encKey, macKey));
}

TEST_CASE("DecryptAsStr Test (2) (fail)") {
    ClientWarden::VaultCrypto crypto(true);
    Botan::secure_vector<uint8_t> encKey = ClientWarden::b64Decode("HkpT6z8HAIrdUjMlMBcPDprnYFe4e6Lfius7YhNmCkY=");
    Botan::secure_vector<uint8_t> macKey = ClientWarden::b64Decode("AtHPCgB/SlDnlEf9WA0JMtl63oDkLpVnPCZJlyOL01s=");

    /*
     * Invalid Decrypt String
    */
    REQUIRE_THROWS(crypto.DecryptAsStr("2.bt==|Ocli+ent==|fi/xxx/mejJmBUCPLZV2iog=", encKey, macKey));
}

TEST_CASE("DecryptRaw Test (1) (fail)") {
    ClientWarden::VaultCrypto crypto(true);

    /*
     * Wrong Mac Key
    */
    Botan::secure_vector<uint8_t> encKey = ClientWarden::b64Decode("Ay1c+hUhNSwVi9XkYg+WDEG6wV4IvfYA0juwbBrptKA=");
    Botan::secure_vector<uint8_t> macKey = ClientWarden::b64Decode("5xkE6NUAROZOl6LhnVHdBh7ydAX4RkxDRAIuuRK86tw=");

    REQUIRE_THROWS(crypto.DecryptRaw(
        ClientWarden::b64Decode("AmKtjLq1L7nHSI9mNmdAJMDQ7Gsp21otZstoMlYUrwHBV2eVleasB3JEThlMT3oqgNM6P/tDsLwSflWF6lig1PY="), encKey, macKey));
}

TEST_CASE("DecryptRaw Test (2) (fail)") {
    ClientWarden::VaultCrypto crypto(true);
    Botan::secure_vector<uint8_t> encKey = ClientWarden::b64Decode("Ay1c+hUhNSwVi9XkYg+WDEG6wV4IvfYA0juwbBrptKA=");
    Botan::secure_vector<uint8_t> macKey = ClientWarden::b64Decode("4xkE6NUAROZOl6LhnVHdBh7ydAX4RkxDRAIuuRK86tw=");

    /*
     * Invalid Decrypt String
    */
    REQUIRE_THROWS(crypto.DecryptRaw(ClientWarden::b64Decode("WRBNG="), encKey, macKey));
}

TEST_CASE("HashedPassword Test (fail)") {
    ClientWarden::VaultCrypto crypto(true);

    std::string password = "BL1entW@rden!2345";

    REQUIRE_THROWS(crypto.hashedPassword(password, ClientWarden::b64Decode("hh+WwlsyJtGGoAvd2rrtOG2v5EOoA1C4=")));
}

TEST_CASE("Macs Equal Test (fail)") {
    ClientWarden::VaultCrypto crypto(true);

    Botan::secure_vector<uint8_t> macKey(32, 0x1);
    Botan::secure_vector<uint8_t> mac1 = {
        0xaa, 0xbb, 0xcc, 0xdd
    };
    Botan::secure_vector<uint8_t> mac2 = {
        0xaa, 0xbb, 0xcc, 0xdf
    };

    REQUIRE(!crypto.macsEqual(macKey, mac1, mac2));
}