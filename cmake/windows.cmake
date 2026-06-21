function(configure_targets _target)
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
endfunction()

function(buildUI _target)
    target_include_directories(${_target} PRIVATE src/Platforms/Windows vendor/imgui vendor/imgui/backends src/Platforms/Windows/UI/ src/
                                                "${CMAKE_CURRENT_BINARY_DIR}/Generated Files/"
                                                "${CMAKE_CURRENT_BINARY_DIR}/Generated Files/App"
                                                "${CMAKE_CURRENT_BINARY_DIR}/Generated Files/CheckboxField"
                                                "${CMAKE_CURRENT_BINARY_DIR}/Generated Files/CheckboxEditField"
                                                "${CMAKE_CURRENT_BINARY_DIR}/Generated Files/GenericField"
                                                "${CMAKE_CURRENT_BINARY_DIR}/Generated Files/PasskeyField"
                                                "${CMAKE_CURRENT_BINARY_DIR}/Generated Files/AttachmentField"
                                                "${CMAKE_CURRENT_BINARY_DIR}/Generated Files/AttachmentEditField"
                                                "${CMAKE_CURRENT_BINARY_DIR}/Generated Files/GenericEditField"
                                                "${CMAKE_CURRENT_BINARY_DIR}/Generated Files/HiddenField"
                                                "${CMAKE_CURRENT_BINARY_DIR}/Generated Files/HiddenEditField"
                                                "${CMAKE_CURRENT_BINARY_DIR}/Generated Files/LinkedField"
                                                "${CMAKE_CURRENT_BINARY_DIR}/Generated Files/LinkedEditField"
                                                "${CMAKE_CURRENT_BINARY_DIR}/Generated Files/FolderEditField"
                                                "${CMAKE_CURRENT_BINARY_DIR}/Generated Files/Login"
                                                "${CMAKE_CURRENT_BINARY_DIR}/Generated Files/MainWindow"
                                                "${CMAKE_CURRENT_BINARY_DIR}/Generated Files/PasswordField"
                                                "${CMAKE_CURRENT_BINARY_DIR}/Generated Files/PasswordEditField"
                                                "${CMAKE_CURRENT_BINARY_DIR}/Generated Files/TextField"
                                                "${CMAKE_CURRENT_BINARY_DIR}/Generated Files/TextEditField"
                                                "${CMAKE_CURRENT_BINARY_DIR}/Generated Files/TOTPField"
                                                "${CMAKE_CURRENT_BINARY_DIR}/Generated Files/Unlock"
                                                "${CMAKE_CURRENT_BINARY_DIR}/Generated Files/VaultUI"
                                                "${CMAKE_CURRENT_BINARY_DIR}/Generated Files/VaultItem"
                                                "${CMAKE_CURRENT_BINARY_DIR}/Generated Files/DeviceVerify"
                                                "${CMAKE_CURRENT_BINARY_DIR}/Generated Files/WebsiteEditField"
                                                "${CMAKE_CURRENT_BINARY_DIR}/Generated Files/WebsiteField")
    target_sources(${_target} PRIVATE src/Platforms/Windows/Storage/Storage.cpp src/Platforms/Windows/Clipboard/Clipboard.cpp
                                src/Platforms/Windows/UI/app.manifest
                                src/Platforms/Windows/UI/App/App.xaml src/Platforms/Windows/UI/App/App.xaml.cpp src/Platforms/Windows/UI/App/App.xaml.h
                                src/Platforms/Windows/UI/Login/Login.xaml src/Platforms/Windows/UI/Login/Login.xaml.cpp src/Platforms/Windows/UI/Login/Login.xaml.h src/Platforms/Windows/UI/Login/Login.idl
                                src/Platforms/Windows/UI/DeviceVerify/DeviceVerify.xaml src/Platforms/Windows/UI/DeviceVerify/DeviceVerify.xaml.cpp src/Platforms/Windows/UI/DeviceVerify/DeviceVerify.xaml.h src/Platforms/Windows/UI/DeviceVerify/DeviceVerify.idl
                                src/Platforms/Windows/UI/FolderEditField/FolderEditField.xaml src/Platforms/Windows/UI/FolderEditField/FolderEditField.xaml.cpp src/Platforms/Windows/UI/FolderEditField/FolderEditField.xaml.h src/Platforms/Windows/UI/FolderEditField/FolderEditField.idl
                                src/Platforms/Windows/UI/Unlock/Unlock.xaml src/Platforms/Windows/UI/Unlock/Unlock.xaml.cpp src/Platforms/Windows/UI/Unlock/Unlock.xaml.h src/Platforms/Windows/UI/Unlock/Unlock.idl
                                src/Platforms/Windows/UI/VaultUI/VaultUI.xaml src/Platforms/Windows/UI/VaultUI/VaultUI.xaml.cpp src/Platforms/Windows/UI/VaultUI/SidebarUI.cpp src/Platforms/Windows/UI/VaultUI/FolderUI.cpp src/Platforms/Windows/UI/VaultUI/VaultUI.xaml.Copy.cpp src/Platforms/Windows/UI/VaultUI/VaultUI.xaml.h src/Platforms/Windows/UI/VaultUI/VaultUI.idl
                                src/Platforms/Windows/UI/VaultItem/VaultItem.xaml src/Platforms/Windows/UI/VaultItem/VaultItem.xaml.cpp src/Platforms/Windows/UI/VaultItem/VaultItem.xaml.h src/Platforms/Windows/UI/VaultItem/VaultItem.idl
                                src/Platforms/Windows/UI/MainWindow/MainWindow.xaml src/Platforms/Windows/UI/MainWindow/MainWindow.xaml.cpp src/Platforms/Windows/UI/MainWindow/MainWindow.xaml.h src/Platforms/Windows/UI/MainWindow/MainWindow.idl
                                src/Platforms/Windows/UI/GenericField/GenericField.xaml src/Platforms/Windows/UI/GenericField/GenericField.xaml.cpp src/Platforms/Windows/UI/GenericField/GenericField.xaml.h src/Platforms/Windows/UI/GenericField/GenericField.idl
                                src/Platforms/Windows/UI/PasskeyField/PasskeyField.xaml src/Platforms/Windows/UI/PasskeyField/PasskeyField.xaml.cpp src/Platforms/Windows/UI/PasskeyField/PasskeyField.xaml.h src/Platforms/Windows/UI/PasskeyField/PasskeyField.idl
                                src/Platforms/Windows/UI/AttachmentField/AttachmentField.xaml src/Platforms/Windows/UI/AttachmentField/AttachmentField.xaml.cpp src/Platforms/Windows/UI/AttachmentField/AttachmentField.xaml.h src/Platforms/Windows/UI/AttachmentField/AttachmentField.idl
                                src/Platforms/Windows/UI/AttachmentEditField/AttachmentEditField.xaml src/Platforms/Windows/UI/AttachmentEditField/AttachmentEditField.xaml.cpp src/Platforms/Windows/UI/AttachmentEditField/AttachmentEditField.xaml.h src/Platforms/Windows/UI/AttachmentEditField/AttachmentEditField.idl
                                src/Platforms/Windows/UI/GenericEditField/GenericEditField.xaml src/Platforms/Windows/UI/GenericEditField/GenericEditField.xaml.cpp src/Platforms/Windows/UI/GenericEditField/GenericEditField.xaml.h src/Platforms/Windows/UI/GenericEditField/GenericEditField.idl
                                src/Platforms/Windows/UI/PasswordField/PasswordField.xaml src/Platforms/Windows/UI/PasswordField/PasswordField.xaml.cpp src/Platforms/Windows/UI/PasswordField/PasswordField.xaml.h src/Platforms/Windows/UI/PasswordField/PasswordField.idl
                                src/Platforms/Windows/UI/PasswordEditField/PasswordEditField.xaml src/Platforms/Windows/UI/PasswordEditField/PasswordEditField.xaml.cpp src/Platforms/Windows/UI/PasswordEditField/PasswordEditField.xaml.h src/Platforms/Windows/UI/PasswordEditField/PasswordEditField.idl
                                src/Platforms/Windows/UI/TOTPField/TOTPField.xaml src/Platforms/Windows/UI/TOTPField/TOTPField.xaml.cpp src/Platforms/Windows/UI/TOTPField/TOTPField.xaml.h src/Platforms/Windows/UI/TOTPField/TOTPField.idl
                                src/Platforms/Windows/UI/TextField/TextField.xaml src/Platforms/Windows/UI/TextField/TextField.xaml.cpp src/Platforms/Windows/UI/TextField/TextField.xaml.h src/Platforms/Windows/UI/TextField/TextField.idl
                                src/Platforms/Windows/UI/TextEditField/TextEditField.xaml src/Platforms/Windows/UI/TextEditField/TextEditField.xaml.cpp src/Platforms/Windows/UI/TextEditField/TextEditField.xaml.h src/Platforms/Windows/UI/TextEditField/TextEditField.idl
                                src/Platforms/Windows/UI/CheckboxField/CheckboxField.xaml src/Platforms/Windows/UI/CheckboxField/CheckboxField.xaml.cpp src/Platforms/Windows/UI/CheckboxField/CheckboxField.xaml.h src/Platforms/Windows/UI/CheckboxField/CheckboxField.idl
                                src/Platforms/Windows/UI/CheckboxEditField/CheckboxEditField.xaml src/Platforms/Windows/UI/CheckboxEditField/CheckboxEditField.xaml.cpp src/Platforms/Windows/UI/CheckboxEditField/CheckboxEditField.xaml.h src/Platforms/Windows/UI/CheckboxEditField/CheckboxEditField.idl
                                src/Platforms/Windows/UI/HiddenField/HiddenField.xaml src/Platforms/Windows/UI/HiddenField/HiddenField.xaml.cpp src/Platforms/Windows/UI/HiddenField/HiddenField.xaml.h src/Platforms/Windows/UI/HiddenField/HiddenField.idl
                                src/Platforms/Windows/UI/HiddenEditField/HiddenEditField.xaml src/Platforms/Windows/UI/HiddenEditField/HiddenEditField.xaml.cpp src/Platforms/Windows/UI/HiddenEditField/HiddenEditField.xaml.h src/Platforms/Windows/UI/HiddenEditField/HiddenEditField.idl
                                src/Platforms/Windows/UI/LinkedField/LinkedField.xaml src/Platforms/Windows/UI/LinkedField/LinkedField.xaml.cpp src/Platforms/Windows/UI/LinkedField/LinkedField.xaml.h src/Platforms/Windows/UI/LinkedField/LinkedField.idl
                                src/Platforms/Windows/UI/LinkedEditField/LinkedEditField.xaml src/Platforms/Windows/UI/LinkedEditField/LinkedEditField.xaml.cpp src/Platforms/Windows/UI/LinkedEditField/LinkedEditField.xaml.h src/Platforms/Windows/UI/LinkedEditField/LinkedEditField.idl
                                src/Platforms/Windows/UI/WebsiteField/WebsiteField.xaml src/Platforms/Windows/UI/WebsiteField/WebsiteField.xaml.cpp src/Platforms/Windows/UI/WebsiteField/WebsiteField.xaml.h src/Platforms/Windows/UI/WebsiteField/WebsiteField.idl
                                src/Platforms/Windows/UI/WebsiteEditField/WebsiteEditField.xaml src/Platforms/Windows/UI/WebsiteEditField/WebsiteEditField.xaml.cpp src/Platforms/Windows/UI/WebsiteEditField/WebsiteEditField.xaml.h src/Platforms/Windows/UI/WebsiteEditField/WebsiteEditField.idl)
    set_property(
        SOURCE src/Platforms/Windows/UI/App/App.xaml
        PROPERTY VS_XAML_TYPE
        "ApplicationDefinition"
    )

    target_compile_definitions(${_target} PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN _CRT_SECURE_NO_WARNINGS)

    set_property(
        TARGET ${_target}
        PROPERTY VS_PACKAGE_REFERENCES
        "Microsoft.Windows.CppWinRT_2.0.230706.1"
        "Microsoft.WindowsAppSDK_1.4.231115000"
        "Microsoft.Windows.SDK.BuildTools_10.0.22621.756"
        "Microsoft.Windows.ImplementationLibrary_1.0.230629.1"
    )

    target_precompile_headers(${_target} PRIVATE src/Platforms/Windows/UI/pch.h)

    set_target_properties(${_target} PROPERTIES
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

    if(CMAKE_VS_PLATFORM_NAME STREQUAL "ARM64")
        set_target_properties(${_target} PROPERTIES
            VS_GLOBAL_RuntimeIdentifiers "win10-arm64"
            VS_GLOBAL_RuntimeIdentifier "win10-arm64"
        )
    elseif(CMAKE_VS_PLATFORM_NAME STREQUAL "x64")
        set_target_properties(${_target} PROPERTIES
            VS_GLOBAL_RuntimeIdentifiers "win10-x64"
            VS_GLOBAL_RuntimeIdentifier "win10-x64"
        )
    endif()

    get_target_property(SOURCES ${_target} SOURCES)

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
endfunction()