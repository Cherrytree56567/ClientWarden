#include <catch2/catch_test_macros.hpp>
#include "VaultCrypto/VaultCrypto.h"

TEST_CASE("Encrypt/Decrypt round trip") {
    ClientWarden::VaultCrypto crypto(true);
    auto [encKey, macKey] = crypto.generateEncMacKeys();
    Botan::secure_vector<uint8_t> pt = {'h','e','l','l','o'};

    std::string ct = crypto.Encrypt(pt, encKey, macKey);
    auto decrypted = crypto.Decrypt(ct, encKey, macKey);

    REQUIRE(decrypted == pt);
}