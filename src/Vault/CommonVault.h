#pragma once

namespace ClientWarden::Vault {
    enum class AuthState {
        NeedsTOTP,
        NeedsEmailVerification,
        Authenticated,
        Failed
    };

    enum class NetworkState {
        Success,
        Failed,
        NotImpl,
        InvalidAccessToken
    };

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
        SSHKey = 5
    };
}