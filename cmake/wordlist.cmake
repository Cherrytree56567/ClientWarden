# Use Claude to help me with this
function(generate_wordlist txt template out_dir)
    file(STRINGS "${txt}" lines)

    set(entries "")
    set(count 0)
    foreach(word IN LISTS lines)
        string(REGEX REPLACE "^[0-9]+[ \t]+" "" word "${word}")
        string(STRIP "${word}" word)
        if(word STREQUAL "")
            continue()
        endif()

        string(REPLACE "\\" "\\\\" word "${word}")
        string(REPLACE "\"" "\\\"" word "${word}")

        string(APPEND entries "    \"${word}\",\n")
        math(EXPR count "${count} + 1")
    endforeach()

    if(count EQUAL 0)
        message(FATAL_ERROR "Word list ${txt} is empty")
    endif()

    set(WORDLIST_COUNT   ${count})
    set(WORDLIST_ENTRIES "${entries}")

    configure_file("${template}" "${out_dir}/wordlist.h" @ONLY)

    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${txt}" "${template}")
endfunction()