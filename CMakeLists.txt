cmake_minimum_required(VERSION 3.16)
project(ClientWarden VERSION 1.0)

if (APPLE)
    enable_language(OBJCXX)
    enable_language(Swift)
endif()

set(CW_IDENTIFIER com.ct5.clientwarden)
set(CW_VERSION 1.0.0)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_BUILD_TYPE Debug)
if (APPLE)
    set(CMAKE_OSX_DEPLOYMENT_TARGET "13.0" CACHE STRING "Minimum macOS deployment version")
endif()

set(Botan_DIR "build/build/generators")

include(FetchContent)

FetchContent_Declare(
    keychain
    GIT_REPOSITORY https://github.com/Cherrytree56567/keychain
    GIT_TAG master
)

FetchContent_MakeAvailable(keychain)

find_package(OpenSSL REQUIRED)
find_package(spdlog CONFIG REQUIRED)
find_package(Boost REQUIRED)
find_package(Boost REQUIRED COMPONENTS url)
find_package(httplib CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(Botan CONFIG REQUIRED)
find_package(msgpack-cxx CONFIG REQUIRED)

get_target_property(BOTAN_INCLUDES botan::botan INTERFACE_INCLUDE_DIRECTORIES)
message(STATUS "Botan includes: ${BOTAN_INCLUDES}")

if (WIN32)
    include(cmake/windows.cmake)
elseif (APPLE)
    include(cmake/macos.cmake)
else ()
    message(WARNING "Unknown platform: won't build UI")
endif()

if (WIN32)
    configure_targets(clientwarden)
endif()

set(FILES
    src/Vault/CardItem/CardItem.cpp
    src/Vault/CipherQuery/CipherQuery.cpp
    src/Vault/CWThread/CWThread.cpp
    src/Vault/Folder/Folder.cpp
    src/Vault/GenericItem/GenericItem.cpp
    src/Vault/IdentityItem/IdentityItem.cpp
    src/Vault/LoginItem/LoginItem.cpp
    src/Vault/NoteItem/NoteItem.cpp
    src/Vault/PasswordGenerator/PasswordGenerator.cpp
    src/Vault/SSHKeyItem/SSHKeyItem.cpp
    src/Vault/VaultCrypto/VaultCrypto.cpp
    src/Vault/VaultNetwork/VaultNetwork.cpp
    src/Vault/VaultProfile/VaultProfile.cpp
    src/Vault/VaultSession/VaultSession.cpp
    src/Vault/VaultUtils/VaultUtils.cpp
    src/Vault/Vault.cpp
)

if (WIN32)
    add_executable(clientwarden WIN32 ${FILES})
elseif (APPLE)
    add_executable(clientwarden MACOSX_BUNDLE ${FILES})
else()
    add_executable(clientwarden ${FILES})
endif()

if (WIN32 OR APPLE)
    buildUI(clientwarden)
endif()

if(MSVC)
    target_compile_options(clientwarden PRIVATE /std:c++latest /GR- /EHa)
endif()

target_link_libraries(clientwarden OpenSSL::Crypto OpenSSL::SSL spdlog::spdlog Boost::boost Boost::url httplib::httplib nlohmann_json::nlohmann_json botan::botan msgpack-cxx keychain)
target_compile_definitions(clientwarden PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT)