set(CW_LAST_RELEASE_HASH "9c36991")

# Versioning
# Format: XXXXY1Z
# XXXX - Number of GH Builds or Commits after last release
# Y - Local or Github Actions or Release (Can be X - Local, A - GH Actions or Y - Release)
# 1 - Major Version
# Z - Platform (P - Windows, L - Linux, M - Mac)
if(DEFINED ENV{GITHUB_RUN_NUMBER})
    set(CW_BUILD_NUMBER $ENV{GITHUB_RUN_NUMBER})
else()
    execute_process(
        COMMAND git rev-list --count ${CW_LAST_RELEASE_HASH}..HEAD
        OUTPUT_VARIABLE CW_BUILD_NUMBER
        OUTPUT_STRIP_TRAILING_WHITESPACE
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    )
endif()

string(LENGTH "${CW_BUILD_NUMBER}" _len)
math(EXPR _pad "4 - ${_len}")
if(_pad GREATER 0)
    string(REPEAT "0" ${_pad} _zeros)
    set(CW_BUILD_NUMBER "${_zeros}${CW_BUILD_NUMBER}")
endif()

if(DEFINED ENV{GITHUB_ACTIONS})
    set(CW_BUILD_SOURCE "A")
elseif(DEFINED ENV{RELEASE_CW_BUILD})
    set(CW_BUILD_SOURCE "Y")
else()
    set(CW_BUILD_SOURCE "X")
endif()

if(WIN32)
    set(CW_BUILD_PLATFORM "P")
elseif(APPLE)
    set(CW_BUILD_PLATFORM "M")
elseif(UNIX)
    set(CW_BUILD_PLATFORM "L")
endif()

set(CW_VERSION_STRING "1")
set(CW_BUILD_STRING "${CW_BUILD_NUMBER}${CW_BUILD_SOURCE}${CW_VERSION_STRING}${CW_BUILD_PLATFORM}")