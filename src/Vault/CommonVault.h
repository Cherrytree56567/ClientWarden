#pragma once

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

enum CustomFieldType {
    Text,
    Hidden,
    Checkbox,
    Linked
};