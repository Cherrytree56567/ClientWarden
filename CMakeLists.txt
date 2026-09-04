cmake_minimum_required(VERSION 3.22)
project(ClientWarden VERSION 1.0)

if (APPLE)
    enable_language(OBJCXX)
    enable_language(Swift)
endif()

# Mac Specific stuff
set(TEAM_ID "IDABC16767")
set(SHARED_BUNDLE_ID "app.ct5.clientwarden")
set(APP_BUNDLE_ID "com.ct5.clientwarden")

set(CW_IDENTIFIER ${APP_BUNDLE_ID})
set(CW_VERSION 1.0.0)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
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

get_target_property(JSON_INCLUDES
    nlohmann_json::nlohmann_json
    INTERFACE_INCLUDE_DIRECTORIES
)

message(STATUS "nlohmann_json target: nlohmann_json::nlohmann_json")
message(STATUS "nlohmann_json includes: ${JSON_INCLUDES}")

if (WIN32)
    include(cmake/windows.cmake)
elseif (ANDROID)
    include(cmake/android.cmake)
elseif (APPLE)
    include(cmake/linux.cmake) # TODO: Change to macos.cmake
elseif (LINUX)
    include(cmake/linux.cmake)
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
elseif (ANDROID)
    add_library(clientwarden SHARED ${FILES})
elseif (APPLE)
    #add_executable(clientwarden MACOSX_BUNDLE ${FILES}) # We need to remove these for now
    add_library(clientwarden SHARED ${FILES})
elseif (LINUX)
    add_library(clientwarden SHARED ${FILES})
else()
    add_library(clientwarden SHARED ${FILES})
endif()

target_link_libraries(clientwarden PRIVATE OpenSSL::Crypto OpenSSL::SSL spdlog::spdlog Boost::boost Boost::url httplib::httplib nlohmann_json::nlohmann_json botan::botan msgpack-cxx keychain)
target_compile_definitions(clientwarden PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT)

target_include_directories(clientwarden PRIVATE src/Vault src/Platforms/)

if (WIN32 OR APPLE OR LINUX OR ANDROID)
    buildUI(clientwarden)
endif()

if(MSVC)
    target_compile_options(clientwarden PRIVATE /std:c++latest /GR- /EHa)
endif()