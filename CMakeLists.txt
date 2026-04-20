cmake_minimum_required(VERSION 3.16)
project(ClientWarden VERSION 1.0)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_BUILD_TYPE Debug)

set(Botan_DIR "build/build/generators")

find_package(OpenSSL REQUIRED)
find_package(spdlog CONFIG REQUIRED)
find_package(Boost REQUIRED)
find_package(Boost REQUIRED COMPONENTS url)
find_package(httplib CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(Botan CONFIG REQUIRED)

add_executable(clientwarden src/main.cpp src/Vault/Vault.cpp src/Vault/VaultOnline.cpp src/Vault/VaultLogin.cpp src/Vault/VaultCrypto.cpp src/Vault/VaultRefresh.cpp src/Vault/VaultUtils/VaultUtils.cpp src/Vault/LoginItem/LoginItem.cpp src/Vault/CardItem/CardItem.cpp src/Vault/NoteItem/NoteItem.cpp src/Vault/IdentityItem/IdentityItem.cpp src/Vault/Folder/Folder.cpp src/Vault/SSHKeyItem/SSHKeyItem.cpp src/Vault/CipherQuery/CipherQuery.cpp src/Vault/PasswordGenerator/PasswordGenerator.cpp)

if (WIN32)
    target_include_directories(clientwarden PRIVATE src/Platforms/Windows vendor/imgui vendor/imgui/backends)
    target_sources(clientwarden PRIVATE src/Platforms/Windows/Storage/Storage.cpp src/Platforms/Windows/UI/UI.cpp src/Platforms/Windows/UI/AcrylicCompositor.cpp
                                        vendor/imgui/imgui_draw.cpp vendor/imgui/imgui_tables.cpp vendor/imgui/imgui_widgets.cpp vendor/imgui/imgui.cpp vendor/imgui/misc/cpp/imgui_stdlib.cpp
                                        vendor/imgui/backends/imgui_impl_dx11.cpp vendor/imgui/backends/imgui_impl_win32.cpp)
endif()

if(MSVC)
    target_compile_options(clientwarden PRIVATE /std:c++latest /GR-)
endif()

target_link_libraries(clientwarden OpenSSL::Crypto OpenSSL::SSL spdlog::spdlog Boost::boost Boost::url httplib::httplib nlohmann_json::nlohmann_json botan::botan)
target_compile_definitions(clientwarden PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT)