include(cmake/versioning.cmake)

find_package(Qt6 6.5 REQUIRED COMPONENTS Quick)

qt_standard_project_setup(REQUIRES 6.5)

function(buildUI _target)
    qt_add_executable(${_target}
        src/Platforms/Linux/UI/main.cpp
        src/Platforms/Linux/Clipboard/Clipboard.cpp
        src/Platforms/Linux/Storage/Storage.cpp
    )

    target_link_libraries(${_target}
        PRIVATE Qt6::Quick
    )

    qt_add_qml_module(${_target}
        URI ${_target}
        VERSION 1.0
        QML_FILES
            src/Platforms/Linux/UI/App.qml
    )

    target_include_directories(${_target} PRIVATE src/Vault src/Platforms/Linux/)

    if (APPLE)
        set_target_properties(${_target} PROPERTIES
            MACOSX_BUNDLE_INFO_PLIST "${CMAKE_SOURCE_DIR}/src/Platforms/MacOS/Info.plist"
        )
        target_compile_definitions(${_target} PRIVATE MSGPACK_DISABLE_LEGACY_NIL NON_XCODE_BUILD)
    endif()
endfunction()