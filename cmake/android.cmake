include(cmake/versioning.cmake)

function(buildUI _target)
    if (WIN32)
        set(GRADLE_RUN ${CMAKE_CURRENT_SOURCE_DIR}/src/Platforms/Android/UI/gradlew.bat)
    else()
        set(GRADLE_RUN ${CMAKE_CURRENT_SOURCE_DIR}/src/Platforms/Android/UI/gradlew)
    endif()

    add_custom_target(UI ALL
        COMMAND ${GRADLE_RUN} :app:assembleDebug
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src/Platforms/Android/UI/
        COMMENT "Building Android UI through GradleW"
    )

    target_sources(${_target} PRIVATE
        src/Platforms/Android/Clipboard/Clipboard.cpp
        src/Platforms/Android/Storage/Storage.cpp
    )

    target_include_directories(${_target} PRIVATE src/Platforms/Android/)

    if (ANDROID)
        set_target_properties(clientwarden PROPERTIES
            LIBRARY_OUTPUT_DIRECTORY
            ${CMAKE_CURRENT_SOURCE_DIR}/src/Platforms/Android/UI/app/src/main/jniLibs/${ANDROID_ABI}
        )
    endif()

    add_dependencies(UI ${_target})
endfunction()