include(cmake/versioning.cmake)

function(buildUI _target)
    if (WIN32)
        set(GRADLE_RUN src/Platforms/Android/UI/gradlew.bat)
    else()
        set(GRADLE_RUN src/Platforms/Android/UI/gradlew)
    endif()

    add_custom_target(UI
        COMMAND ${GRADLE_RUN} :app:assembleDebug
        WORKING_DIRECTORY src/Platforms/Android/UI/
        COMMENT "Building Android UI through GradleW"
    )

    target_sources(${_target} PRIVATE
        src/Platforms/Linux/Clipboard/Clipboard.cpp
        src/Platforms/Linux/Storage/Storage.cpp
    )

    target_include_directories(${_target} PRIVATE src/Vault src/Platforms/Android/)

    add_dependencies(UI ${_target})
endfunction()