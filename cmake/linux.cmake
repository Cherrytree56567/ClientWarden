include(cmake/versioning.cmake)
include(FetchContent)

FetchContent_Declare(
    Corrosion
    GIT_REPOSITORY https://github.com/corrosion-rs/corrosion.git
    GIT_TAG v0.6
)
FetchContent_MakeAvailable(Corrosion)

function(buildUI _target)
    target_sources(${_target} PRIVATE
        src/Platforms/Linux/Clipboard/Clipboard.cpp
        src/Platforms/Linux/Storage/Storage.cpp
    )
    corrosion_import_crate(MANIFEST_PATH src/Platforms/Linux/Cargo.toml)
    corrosion_link_libraries(UI ${_target})

    target_include_directories(${_target} PRIVATE src/Platforms/Linux/)

    if (APPLE)
        set_target_properties(${_target} PROPERTIES
            MACOSX_BUNDLE_INFO_PLIST "${CMAKE_SOURCE_DIR}/src/Platforms/MacOS/Info.plist"
        )
        target_compile_definitions(${_target} PRIVATE MSGPACK_DISABLE_LEGACY_NIL NON_XCODE_BUILD)

        find_library(CFNETWORK_LIBRARY CFNetwork REQUIRED)
        target_link_libraries(${_target} PRIVATE ${CFNETWORK_LIBRARY})
    endif()
endfunction()