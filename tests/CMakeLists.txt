cmake_minimum_required(VERSION 3.16)

project(ClientWarden.Tests LANGUAGES CXX VERSION 0.0.1)

Include(FetchContent)
include(../cmake/wordlist.cmake)

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

FetchContent_Declare(
    semver
    GIT_REPOSITORY https://github.com/Neargye/semver
    GIT_TAG v0.3.1
)

FetchContent_MakeAvailable(semver)
FetchContent_MakeAvailable(Catch2)
FetchContent_MakeAvailable(keychain)

find_package(OpenSSL REQUIRED)
find_package(spdlog CONFIG REQUIRED)
find_package(Boost REQUIRED)
find_package(Boost REQUIRED COMPONENTS url)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(Botan CONFIG REQUIRED)
find_package(msgpack-cxx CONFIG REQUIRED)
find_package(date CONFIG REQUIRED)

file(GLOB_RECURSE FILES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/core/*.cpp"
)

target_sources(tests PRIVATE 
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/nouiexec/storage/storage.cpp")


add_executable(tests test.cpp crypto/crypto.cpp ${FILES})
target_link_libraries(tests PRIVATE Catch2::Catch2WithMain OpenSSL::Crypto OpenSSL::SSL spdlog::spdlog Boost::boost Boost::url nlohmann_json::nlohmann_json botan::botan msgpack-cxx keychain semver::semver date::date)

generate_wordlist(
    ${CMAKE_CURRENT_SOURCE_DIR}/../assets/wordlist.txt
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/core/password_generator/word_list.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/generated
)

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
    ${CMAKE_CURRENT_BINARY_DIR}/generated/
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/nouiexec/"
    ../src/core 
    ../src/core/vault 
    ../src/platforms/
    httplib
    .
)

target_compile_definitions(tests PRIVATE MSGPACK_DISABLE_LEGACY_NIL)

if (APPLE)
    add_custom_command(TARGET tests POST_BUILD
        COMMAND codesign --force --deep --sign - $<TARGET_FILE:tests>
        COMMENT "Sign Bin to prevent failure"
    )
endif()

include(CTest)
include(Catch)
catch_discover_tests(tests)