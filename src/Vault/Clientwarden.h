#pragma once
#include <spdlog/spdlog.h>

namespace ClientWarden {
    enum class CustomFieldType {
        Text,
        Hidden,
        Checkbox,
        Linked
    };

    enum class CipherType {
        Login = 1,
        Card = 3,
        Identity = 4,
        Note = 2,
        SSHKey = 5,
        Generic = 0
    };

    inline static std::shared_ptr<spdlog::logger> logger = nullptr;
}