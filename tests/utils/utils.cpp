#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/generators/catch_generators_range.hpp>
#include "VaultUtils/VaultUtils.h"

TEST_CASE("Base 64 Encode Test") {
    Botan::secure_vector<uint8_t> og = {
        'C', 'l', '1', 'e', 'n', 't', 'W', '@', 'r', '\\', 'e', 'n'
    };

    std::string result = ClientWarden::b64Encode(og);

    REQUIRE(result == "Q2wxZW50V0ByXGVu");
}

TEST_CASE("Base 64 Decode Test") {
    Botan::secure_vector<uint8_t> og = {
        'C', 'l', '1', 'e', 'n', 't', 'W', '@', 'r', '\\', 'e', 'n'
    };

    Botan::secure_vector<uint8_t> result = ClientWarden::b64Decode("Q2wxZW50V0ByXGVu");

    REQUIRE(result == og);
}

TEST_CASE("getBitwardenTime/BitwardenTime Test") {
    int i = GENERATE(range(0, 10));
    CAPTURE(i);
    
    std::time_t t1 = std::time(nullptr);

    std::string res = ClientWarden::getBitwardenTime();
    std::time_t result = ClientWarden::BitwardenTime(res);

    std::time_t t2 = std::time(nullptr);

    REQUIRE(result >= t1);
    REQUIRE(result <= t2);
}

TEST_CASE("BitwardenTime Test") {
    std::time_t result = ClientWarden::BitwardenTime("2026-08-22T06:53:51.78Z");

    REQUIRE(result == 1787381631);
}