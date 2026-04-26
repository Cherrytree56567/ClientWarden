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

get_target_property(BOTAN_INCLUDES botan::botan INTERFACE_INCLUDE_DIRECTORIES)
message(STATUS "Botan includes: ${BOTAN_INCLUDES}")

if (WIN32)
    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/src/Platforms/Windows/UI/Directory.Build.props"
        "${CMAKE_CURRENT_BINARY_DIR}/Directory.Build.props"
        COPYONLY
    )
    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/src/Platforms/Windows/UI/Directory.Build.targets"
        "${CMAKE_CURRENT_BINARY_DIR}/Directory.Build.targets"
        COPYONLY
    )
endif()

if (WIN32)
    add_executable(clientwarden WIN32 src/main.cpp src/Vault/Vault.cpp src/Vault/VaultOnline.cpp src/Vault/VaultLogin.cpp src/Vault/VaultCrypto.cpp src/Vault/VaultRefresh.cpp src/Vault/VaultUtils/VaultUtils.cpp src/Vault/LoginItem/LoginItem.cpp src/Vault/CardItem/CardItem.cpp src/Vault/NoteItem/NoteItem.cpp src/Vault/IdentityItem/IdentityItem.cpp src/Vault/Folder/Folder.cpp src/Vault/SSHKeyItem/SSHKeyItem.cpp src/Vault/CipherQuery/CipherQuery.cpp src/Vault/PasswordGenerator/PasswordGenerator.cpp)
else()
    add_executable(clientwarden src/main.cpp src/Vault/Vault.cpp src/Vault/VaultOnline.cpp src/Vault/VaultLogin.cpp src/Vault/VaultCrypto.cpp src/Vault/VaultRefresh.cpp src/Vault/VaultUtils/VaultUtils.cpp src/Vault/LoginItem/LoginItem.cpp src/Vault/CardItem/CardItem.cpp src/Vault/NoteItem/NoteItem.cpp src/Vault/IdentityItem/IdentityItem.cpp src/Vault/Folder/Folder.cpp src/Vault/SSHKeyItem/SSHKeyItem.cpp src/Vault/CipherQuery/CipherQuery.cpp src/Vault/PasswordGenerator/PasswordGenerator.cpp)
endif()

if (WIN32)
    target_include_directories(clientwarden PRIVATE src/Platforms/Windows vendor/imgui vendor/imgui/backends src/Platforms/Windows/UI/ src/
                                            "${CMAKE_CURRENT_BINARY_DIR}/Generated Files/"
                                            "${CMAKE_CURRENT_BINARY_DIR}/Generated Files/App"
                                            "${CMAKE_CURRENT_BINARY_DIR}/Generated Files/CheckboxField"
                                            "${CMAKE_CURRENT_BINARY_DIR}/Generated Files/GenericField"
                                            "${CMAKE_CURRENT_BINARY_DIR}/Generated Files/HiddenField"
                                            "${CMAKE_CURRENT_BINARY_DIR}/Generated Files/LinkedField"
                                            "${CMAKE_CURRENT_BINARY_DIR}/Generated Files/Login"
                                            "${CMAKE_CURRENT_BINARY_DIR}/Generated Files/MainWindow"
                                            "${CMAKE_CURRENT_BINARY_DIR}/Generated Files/PasswordField"
                                            "${CMAKE_CURRENT_BINARY_DIR}/Generated Files/TextField"
                                            "${CMAKE_CURRENT_BINARY_DIR}/Generated Files/TOTPField"
                                            "${CMAKE_CURRENT_BINARY_DIR}/Generated Files/Unlock"
                                            "${CMAKE_CURRENT_BINARY_DIR}/Generated Files/VaultUI"
                                            "${CMAKE_CURRENT_BINARY_DIR}/Generated Files/VaultItem"
                                            "${CMAKE_CURRENT_BINARY_DIR}/Generated Files/WebsiteField")
    target_sources(clientwarden PRIVATE src/Platforms/Windows/Storage/Storage.cpp
                                src/Platforms/Windows/UI/app.manifest
                                src/Platforms/Windows/UI/App/App.xaml src/Platforms/Windows/UI/App/App.xaml.cpp src/Platforms/Windows/UI/App/App.xaml.h
                                src/Platforms/Windows/UI/Login/Login.xaml src/Platforms/Windows/UI/Login/Login.xaml.cpp src/Platforms/Windows/UI/Login/Login.xaml.h src/Platforms/Windows/UI/Login/Login.idl
                                src/Platforms/Windows/UI/Unlock/Unlock.xaml src/Platforms/Windows/UI/Unlock/Unlock.xaml.cpp src/Platforms/Windows/UI/Unlock/Unlock.xaml.h src/Platforms/Windows/UI/Unlock/Unlock.idl
                                src/Platforms/Windows/UI/VaultUI/VaultUI.xaml src/Platforms/Windows/UI/VaultUI/VaultUI.xaml.cpp src/Platforms/Windows/UI/VaultUI/VaultUI.xaml.h src/Platforms/Windows/UI/VaultUI/VaultUI.idl
                                src/Platforms/Windows/UI/VaultItem/VaultItem.xaml src/Platforms/Windows/UI/VaultItem/VaultItem.xaml.cpp src/Platforms/Windows/UI/VaultItem/VaultItem.xaml.h src/Platforms/Windows/UI/VaultItem/VaultItem.idl
                                src/Platforms/Windows/UI/MainWindow/MainWindow.xaml src/Platforms/Windows/UI/MainWindow/MainWindow.xaml.cpp src/Platforms/Windows/UI/MainWindow/MainWindow.xaml.h src/Platforms/Windows/UI/MainWindow/MainWindow.idl
                                src/Platforms/Windows/UI/GenericField/GenericField.xaml src/Platforms/Windows/UI/GenericField/GenericField.xaml.cpp src/Platforms/Windows/UI/GenericField/GenericField.xaml.h src/Platforms/Windows/UI/GenericField/GenericField.idl
                                src/Platforms/Windows/UI/PasswordField/PasswordField.xaml src/Platforms/Windows/UI/PasswordField/PasswordField.xaml.cpp src/Platforms/Windows/UI/PasswordField/PasswordField.xaml.h src/Platforms/Windows/UI/PasswordField/PasswordField.idl
                                src/Platforms/Windows/UI/TOTPField/TOTPField.xaml src/Platforms/Windows/UI/TOTPField/TOTPField.xaml.cpp src/Platforms/Windows/UI/TOTPField/TOTPField.xaml.h src/Platforms/Windows/UI/TOTPField/TOTPField.idl
                                src/Platforms/Windows/UI/TextField/TextField.xaml src/Platforms/Windows/UI/TextField/TextField.xaml.cpp src/Platforms/Windows/UI/TextField/TextField.xaml.h src/Platforms/Windows/UI/TextField/TextField.idl
                                src/Platforms/Windows/UI/CheckboxField/CheckboxField.xaml src/Platforms/Windows/UI/CheckboxField/CheckboxField.xaml.cpp src/Platforms/Windows/UI/CheckboxField/CheckboxField.xaml.h src/Platforms/Windows/UI/CheckboxField/CheckboxField.idl
                                src/Platforms/Windows/UI/HiddenField/HiddenField.xaml src/Platforms/Windows/UI/HiddenField/HiddenField.xaml.cpp src/Platforms/Windows/UI/HiddenField/HiddenField.xaml.h src/Platforms/Windows/UI/HiddenField/HiddenField.idl
                                src/Platforms/Windows/UI/LinkedField/LinkedField.xaml src/Platforms/Windows/UI/LinkedField/LinkedField.xaml.cpp src/Platforms/Windows/UI/LinkedField/LinkedField.xaml.h src/Platforms/Windows/UI/LinkedField/LinkedField.idl
                                src/Platforms/Windows/UI/WebsiteField/WebsiteField.xaml src/Platforms/Windows/UI/WebsiteField/WebsiteField.xaml.cpp src/Platforms/Windows/UI/WebsiteField/WebsiteField.xaml.h src/Platforms/Windows/UI/WebsiteField/WebsiteField.idl)
    set_property(
        SOURCE src/Platforms/Windows/UI/App/App.xaml
        PROPERTY VS_XAML_TYPE
        "ApplicationDefinition"
    )

    target_compile_definitions(clientwarden PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN _CRT_SECURE_NO_WARNINGS)

    set_property(
        TARGET clientwarden
        PROPERTY VS_PACKAGE_REFERENCES
        "Microsoft.Windows.CppWinRT_2.0.230706.1"
        "Microsoft.WindowsAppSDK_1.4.231115000"
        "Microsoft.Windows.SDK.BuildTools_10.0.22621.756"
        "Microsoft.Windows.ImplementationLibrary_1.0.230629.1"
    )

    target_precompile_headers(clientwarden PRIVATE src/Platforms/Windows/UI/pch.h)

    set_target_properties(
        clientwarden
        PROPERTIES
        VS_GLOBAL_RootNamespace WindowsUI
        VS_GLOBAL_AppContainerApplication false
        VS_GLOBAL_AppxPackage false
        VS_GLOBAL_CppWinRTOptimized true
        VS_GLOBAL_CppWinRTRootNamespaceAutoMerge true
        VS_GLOBAL_UseWinUI true
        VS_GLOBAL_ApplicationType "Windows Store"
        VS_GLOBAL_WindowsPackageType None
        VS_GLOBAL_EnablePreviewMsixTooling true
        VS_GLOBAL_WindowsAppSDKSelfContained true
    )

    get_target_property(SOURCES clientwarden SOURCES)

    foreach(SOURCE ${SOURCES})
        cmake_path(GET SOURCE EXTENSION LAST_ONLY EXTENSION)
        if(NOT "${EXTENSION}" STREQUAL ".idl")
            continue()
        endif()

        set(IDL_SOURCE "${SOURCE}")
        cmake_path(REMOVE_EXTENSION SOURCE LAST_ONLY OUTPUT_VARIABLE BASENAME)
        set(XAML_SOURCE "${BASENAME}.xaml")

        # Get just the filename for DependentUpon
        cmake_path(GET BASENAME FILENAME BASENAME_FILENAME)

        if("${XAML_SOURCE}" IN_LIST SOURCES)
            set_property(SOURCE "${IDL_SOURCE}" PROPERTY VS_SETTINGS
                "SubType=Code"
                "DependentUpon=${BASENAME_FILENAME}.xaml"
            )
        else()
            set_property(SOURCE "${IDL_SOURCE}" PROPERTY VS_SETTINGS "SubType=Code")
            set_property(SOURCE "${BASENAME}.h" PROPERTY VS_SETTINGS
                "DependentUpon=${BASENAME_FILENAME}.idl"
            )
            set_property(SOURCE "${BASENAME}.cpp" PROPERTY VS_SETTINGS
                "DependentUpon=${BASENAME_FILENAME}.idl"
            )
        endif()
    endforeach()
endif()

if(MSVC)
    target_compile_options(clientwarden PRIVATE /std:c++latest /GR-)
endif()

target_link_libraries(clientwarden OpenSSL::Crypto OpenSSL::SSL spdlog::spdlog Boost::boost Boost::url httplib::httplib nlohmann_json::nlohmann_json botan::botan)
target_compile_definitions(clientwarden PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT)