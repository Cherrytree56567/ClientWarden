cmake_minimum_required(VERSION 3.22)
project(ClientWarden VERSION 1.0)

message(STATUS "WIN32=${WIN32} APPLE=${APPLE} ANDROID=${ANDROID} LINUX=${LINUX} UNIX=${UNIX}")

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

set(BW_VERSION "2026.3.0")

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if (APPLE)
    set(CMAKE_OSX_DEPLOYMENT_TARGET "14.0" CACHE STRING "Minimum macOS deployment version")
endif()

set(Botan_DIR "build/build/generators")

include(FetchContent)
include(cmake/wordlist.cmake)

FetchContent_Declare(
    keychain
    GIT_REPOSITORY https://github.com/Cherrytree56567/keychain
    GIT_TAG master
)

FetchContent_MakeAvailable(keychain)

FetchContent_Declare(
    semver
    GIT_REPOSITORY https://github.com/Neargye/semver
    GIT_TAG v0.3.1
)
FetchContent_MakeAvailable(semver)

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

if(WIN32)
    set(_default_target windows)
elseif(APPLE)
    if(CMAKE_SYSTEM_NAME STREQUAL "iOS")
        set(_default_target _ios)
    else()
        set(_default_target macos)
    endif()
elseif(ANDROID)
    set(_default_target _android)
elseif(UNIX)
    set(_default_target _linux)
else()
    set(_default_target _library)
endif()

set(CW_PLATFORM "${_default_target}" CACHE STRING "Platform Target")
set(CW_PLATFORM_VALUES windows macos _linux _android _ios _library _nonuiexec)
set_property(CACHE CW_PLATFORM PROPERTY STRINGS ${CW_PLATFORM_VALUES})

message(STATUS "CW_PLATFORM=${CW_PLATFORM}")

if(NOT CW_PLATFORM IN_LIST CW_PLATFORM_VALUES)
    message(FATAL_ERROR "Invalid Target")
endif()

if(CW_PLATFORM STREQUAL "windows")
    message(FATAL_ERROR "Unimplemented platform: ${CW_PLATFORM}")

    include(cmake/windows.cmake)
elseif(CW_PLATFORM STREQUAL "_android")
    message(FATAL_ERROR "Unimplemented platform: ${CW_PLATFORM}")
    
    include(cmake/android.cmake)
elseif(CW_PLATFORM STREQUAL "_linux")
    message(FATAL_ERROR "Unimplemented platform: ${CW_PLATFORM}")
    
    include(cmake/linux.cmake)
elseif(CW_PLATFORM STREQUAL "macos")
    include(cmake/macos.cmake)
elseif(CW_PLATFORM STREQUAL "_library")

elseif(CW_PLATFORM STREQUAL "_nonuiexec")

else ()
    message(FATAL_ERROR "Unimplemented platform: ${CW_PLATFORM}")
endif()

if (WIN32)
    configure_targets(clientwarden)
endif()

file(GLOB_RECURSE FILES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/core/*.cpp"
)

if(CW_PLATFORM STREQUAL "windows")
    add_executable(clientwarden WIN32 ${FILES})
elseif(CW_PLATFORM STREQUAL "_android")
    add_library(clientwarden SHARED ${FILES})
elseif(CW_PLATFORM STREQUAL "_linux")
    add_library(clientwarden SHARED ${FILES})
elseif(CW_PLATFORM STREQUAL "macos")
    add_executable(clientwarden MACOSX_BUNDLE ${FILES})
    #add_library(clientwarden SHARED ${FILES}) # Remove comment to use Linux Build on MacOS
elseif(CW_PLATFORM STREQUAL "_library")
    add_library(clientwarden SHARED ${FILES})
elseif(CW_PLATFORM STREQUAL "_nonuiexec")
    add_executable(clientwarden ${FILES})

    target_sources(clientwarden PRIVATE 
        "${CMAKE_CURRENT_SOURCE_DIR}/src/nouiexec/storage/storage.cpp")

    target_include_directories(clientwarden PRIVATE 
        "${CMAKE_CURRENT_SOURCE_DIR}/src/nouiexec/")
else()
    message(FATAL_ERROR "Unimplemented platform: ${CW_PLATFORM}")
endif()

generate_wordlist(
    ${CMAKE_CURRENT_SOURCE_DIR}/assets/wordlist.txt
    ${CMAKE_CURRENT_SOURCE_DIR}/src/core/password_generator/word_list.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/generated
)

target_link_libraries(clientwarden PRIVATE OpenSSL::Crypto OpenSSL::SSL spdlog::spdlog Boost::boost Boost::url httplib::httplib nlohmann_json::nlohmann_json botan::botan msgpack-cxx keychain semver::semver)
target_compile_definitions(clientwarden PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT MSGPACK_DISABLE_LEGACY_NIL APP_TYPE="${APP_TYPE}" APP_ID="${APP_BUNDLE_ID}" BW_VERSION="${BW_VERSION}")

target_include_directories(clientwarden PRIVATE src/core src/core/vault src/Platforms/ ${CMAKE_CURRENT_BINARY_DIR}/generated/)

if (ANDROID)
    target_compile_options(clientwarden PRIVATE -fexperimental-library)
    target_link_options(clientwarden PRIVATE -fexperimental-library)
endif()

if (CW_PLATFORM STREQUAL "windows" OR 
    CW_PLATFORM STREQUAL "macos" OR 
    CW_PLATFORM STREQUAL "_linux" OR 
    CW_PLATFORM STREQUAL "_android")
    buildUI(clientwarden)
endif()

if(MSVC)
    target_compile_options(clientwarden PRIVATE /std:c++latest /GR- /EHa)
endif()
