cmake_minimum_required(VERSION 3.16)

project(ClientWarden.Tests LANGUAGES CXX VERSION 0.0.1)

Include(FetchContent)

# From Catch2 Docs
# https://github.com/catchorg/Catch2
FetchContent_Declare(
  Catch2
  GIT_REPOSITORY https://github.com/catchorg/Catch2.git
  GIT_TAG        v3.15.3 # or a later release
)

FetchContent_Declare(
    keychain
    GIT_REPOSITORY https://github.com/Cherrytree56567/keychain
    GIT_TAG master
)

FetchContent_MakeAvailable(Catch2)
FetchContent_MakeAvailable(keychain)

find_package(OpenSSL REQUIRED)
find_package(spdlog CONFIG REQUIRED)
find_package(Boost REQUIRED)
find_package(Boost REQUIRED COMPONENTS url)
find_package(httplib CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(Botan CONFIG REQUIRED)
find_package(msgpack-cxx CONFIG REQUIRED)

set(FILES
    ../src/Vault/CardItem/CardItem.cpp
    ../src/Vault/CipherQuery/CipherQuery.cpp
    ../src/Vault/CWThread/CWThread.cpp
    ../src/Vault/Folder/Folder.cpp
    ../src/Vault/GenericItem/GenericItem.cpp
    ../src/Vault/IdentityItem/IdentityItem.cpp
    ../src/Vault/LoginItem/LoginItem.cpp
    ../src/Vault/NoteItem/NoteItem.cpp
    ../src/Vault/PasswordGenerator/PasswordGenerator.cpp
    ../src/Vault/SSHKeyItem/SSHKeyItem.cpp
    ../src/Vault/VaultCrypto/VaultCrypto.cpp
    ../src/Vault/VaultNetwork/VaultNetwork.cpp
    ../src/Vault/VaultProfile/VaultProfile.cpp
    ../src/Vault/VaultSession/VaultSession.cpp
    ../src/Vault/VaultUtils/VaultUtils.cpp
    ../src/Vault/Vault.cpp
    Storage/Storage.cpp
    Clipboard/Clipboard.cpp
)


add_executable(tests test.cpp crypto/crypto_pbkdf.cpp crypto/crypto_pbkdf_fail.cpp utils/utils.cpp ${FILES})
target_link_libraries(tests PRIVATE Catch2::Catch2WithMain OpenSSL::Crypto OpenSSL::SSL spdlog::spdlog Boost::boost Boost::url httplib::httplib nlohmann_json::nlohmann_json botan::botan msgpack-cxx keychain)

if(APPLE)
    find_library(CFNETWORK_FRAMEWORK CFNetwork REQUIRED)
    target_link_libraries(tests PRIVATE ${CFNETWORK_FRAMEWORK})
    set_target_properties(tests PROPERTIES
        XCODE_ATTRIBUTE_CODE_SIGN_IDENTITY "-"
        XCODE_ATTRIBUTE_CODE_SIGNING_REQUIRED "YES"
        XCODE_ATTRIBUTE_CODE_SIGNING_ALLOWED "YES"
    )
endif()

target_include_directories(tests PUBLIC
    ../src/Vault
    .
)

target_compile_definitions(tests PRIVATE MSGPACK_DISABLE_LEGACY_NIL)

add_custom_command(TARGET tests POST_BUILD
    COMMAND codesign --force --deep --sign - $<TARGET_FILE:tests>
    COMMENT "Sign Bin to prevent failure"
)

include(CTest)
include(Catch)
catch_discover_tests(tests)