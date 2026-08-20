include(cmake/versioning.cmake)

function(buildUI _target)
    configure_file(
        src/Platforms/MacOS/UI/Clientwarden/CMake.swift.in
        ${CMAKE_BINARY_DIR}/generated/CMake.swift
        @ONLY
    )

    add_library(ClientwardenAutoFill MODULE
        ${CMAKE_BINARY_DIR}/generated/CMake.swift
        src/Platforms/MacOS/ClientwardenAutofill/CredentialProviderViewController.swift
    )

    set_target_properties(ClientwardenAutoFill PROPERTIES
        BUNDLE TRUE
        XCODE_ATTRIBUTE_PRODUCT_NAME "ClientwardenAutoFill"
        XCODE_ATTRIBUTE_WRAPPER_EXTENSION "appex"
        XCODE_ATTRIBUTE_PRODUCT_TYPE "com.apple.product-type.app-extension"
        XCODE_ATTRIBUTE_SWIFT_VERSION "5.0"
        XCODE_ATTRIBUTE_SDKROOT "macosx"
        XCODE_ATTRIBUTE_MACOSX_DEPLOYMENT_TARGET "13.0"
        XCODE_ATTRIBUTE_CODE_SIGN_ENTITLEMENTS "${CMAKE_SOURCE_DIR}/src/Platforms/MacOS/ClientwardenAutofill/ClientwardenAutofill.entitlements"
        MACOSX_BUNDLE_INFO_PLIST "${CMAKE_SOURCE_DIR}/src/Platforms/MacOS/ClientwardenAutofill/Info.plist"
    )

    add_dependencies(${_target} ClientwardenAutoFill)

    set(SwiftUI
        src/Platforms/MacOS/UI/Clientwarden/AboutView.swift
        src/Platforms/MacOS/UI/Clientwarden/ActivityMonitor.swift
        src/Platforms/MacOS/UI/Clientwarden/AutofillUnlockView.swift
        src/Platforms/MacOS/UI/Clientwarden/SDKHandler.swift
        src/Platforms/MacOS/UI/Clientwarden/Clientwarden.swift
        src/Platforms/MacOS/UI/Clientwarden/ClientwardenApp.swift
        src/Platforms/MacOS/UI/Clientwarden/ClientwardenImage.swift
        src/Platforms/MacOS/UI/Clientwarden/Clipboard.swift
        src/Platforms/MacOS/UI/Clientwarden/FieldItem.swift
        src/Platforms/MacOS/UI/Clientwarden/GenericItem.swift
        src/Platforms/MacOS/UI/Clientwarden/ItemElement.swift
        src/Platforms/MacOS/UI/Clientwarden/ItemsPanel.swift
        src/Platforms/MacOS/UI/Clientwarden/NavigationPanel.swift
        src/Platforms/MacOS/UI/Clientwarden/PreviewData.swift
        src/Platforms/MacOS/UI/Clientwarden/SidePanel.swift
        src/Platforms/MacOS/UI/Clientwarden/Unlock.swift
        src/Platforms/MacOS/UI/Clientwarden/Login.swift
        src/Platforms/MacOS/UI/Clientwarden/SettingsView.swift
        src/Platforms/MacOS/UI/Clientwarden/AttachmentItem.swift
        src/Platforms/MacOS/UI/Clientwarden/Toast.swift
        ${CMAKE_BINARY_DIR}/generated/CMake.swift
    )

    set(SwiftUIAssets
        src/Platforms/MacOS/UI/Clientwarden/Assets.xcassets
        src/Platforms/MacOS/UI/Clientwarden/Resources/MacOSIcon.icon
        ClientWarden/clientgen.txt
    )

    set_source_files_properties(${SwiftUIAssets} PROPERTIES
        MACOSX_PACKAGE_LOCATION Resources
    )

    set(MAC_FILES
        src/Platforms/MacOS/Storage/Storage.mm 
        src/Platforms/MacOS/Clipboard/Clipboard.mm
        src/Platforms/MacOS/Clipboard/ClipboardBridge.mm
        src/Platforms/MacOS/UIBridge/CWAppBridge.mm
        src/Platforms/MacOS/UIBridge/LoginBridge.mm
        src/Platforms/MacOS/UIBridge/UnlockBridge.mm
        src/Platforms/MacOS/UIBridge/NavPanelBridge.mm
        src/Platforms/MacOS/UIBridge/ItemsPanelBridge.mm
        src/Platforms/MacOS/UIBridge/SidePanelBridge.mm
        src/Platforms/MacOS/UIBridge/SettingsBridge.mm
        src/Platforms/MacOS/UIBridge/ActivityMonitorBridge.mm
        src/Platforms/MacOS/UIBridge/SDKHandlerBridge.mm
    )
    
    target_sources(${_target} PRIVATE ${MAC_FILES} ${SwiftUI} ${SwiftUIAssets} ${ICON_FILE})
    target_include_directories(${_target} PRIVATE src/Platforms/MacOS src/Vault)
    target_link_libraries(${_target} "-framework Cocoa")
    target_compile_definitions(${_target} PRIVATE MSGPACK_DISABLE_LEGACY_NIL NON_XCODE_BUILD)
    set_target_properties(${_target} PROPERTIES
        MACOSX_BUNDLE_GUI_IDENTIFIER ${CW_IDENTIFIER}
        MACOSX_BUNDLE_BUNDLE_VERSION "${CW_BUILD_STRING}"
        MACOSX_BUNDLE_SHORT_VERSION_STRING "${CW_BUILD_STRING}"
        MACOSX_BUNDLE_INFO_PLIST "${CMAKE_SOURCE_DIR}/src/Platforms/MacOS/Info.plist"
        #XCODE_ATTRIBUTE_CODE_SIGN_ENTITLEMENTS "${CMAKE_SOURCE_DIR}/src/Platforms/MacOS/Clientwarden.entitlements"
        XCODE_ATTRIBUTE_SWIFT_OBJC_BRIDGING_HEADER "${CMAKE_SOURCE_DIR}/src/Platforms/MacOS/Bridge.h"
        XCODE_ATTRIBUTE_ASSETCATALOG_COMPILER_APPICON_NAME "MacOSIcon"
        XCODE_EMBED_APP_EXTENSIONS ClientwardenAutoFill
    )
endfunction()