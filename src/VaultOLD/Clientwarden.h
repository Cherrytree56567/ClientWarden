#pragma once
#include <spdlog/spdlog.h>

namespace ClientWarden {
    enum class CustomFieldType {
        Text,
        Hidden,
        Checkbox,
        Linked
    };

    /*
     * From Vault Warden
     * https://github.com/dani-garcia/vaultwarden/blob/eb212e23fad88e6136723f43e5b73543fa7026d3/src/db/models/cipher.rs#L51
     * See (v2026.7.0): https://github.com/bitwarden/server/blob/5d4461aa42cadbacfef8fe2166c5453a5c52773a/src/Core/Vault/Enums/CipherType.cs
    */
    enum class CipherType {
        Login = 1,
        Card = 3,
        Identity = 4,
        Note = 2,
        SSHKey = 5,
        BankAccount = 6,
        DriversLicense = 7,
        Passport = 8,
        Generic = 0
    };

    inline std::shared_ptr<spdlog::logger> logger = nullptr;
}