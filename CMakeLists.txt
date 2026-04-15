cmake_minimum_required(VERSION 3.16)
project(ClientWarden VERSION 1.0)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_BUILD_TYPE Debug)

find_package(OpenSSL REQUIRED)
find_package(spdlog CONFIG REQUIRED)
find_package(Boost REQUIRED)
find_package(httplib CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)

add_executable(clientwarden src/main.cpp src/Vault/Vault.cpp src/Vault/VaultOnline.cpp src/Vault/VaultLogin.cpp src/Vault/VaultCrypto.cpp src/Vault/VaultRefresh.cpp src/Vault/VaultUtils/VaultUtils.cpp src/Vault/LoginItem/LoginItem.cpp src/Vault/CardItem/CardItem.cpp src/Vault/NoteItem/NoteItem.cpp src/Vault/IdentityItem/IdentityItem.cpp src/Vault/Folder/Folder.cpp src/Vault/SSHKeyItem/SSHKeyItem.cpp src/Vault/CipherQuery/CipherQuery.cpp)

if (WIN32)
    target_include_directories(clientwarden PRIVATE src/Platforms/Windows)
    target_sources(clientwarden PRIVATE src/Platforms/Windows/Storage/Storage.cpp)
endif()

if(MSVC)
    target_compile_options(clientwarden PRIVATE /std:c++latest)
endif()

target_link_libraries(clientwarden OpenSSL::Crypto OpenSSL::SSL spdlog::spdlog Boost::boost httplib::httplib nlohmann_json::nlohmann_json)
target_compile_definitions(clientwarden PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT)