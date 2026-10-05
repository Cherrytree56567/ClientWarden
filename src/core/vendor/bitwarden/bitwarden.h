#pragma once
#include <string>
#include <string_view>

namespace clientwarden::vendor::bitwarden {
    enum class DeviceType : uint8_t {
        Android = 0,
        iOS = 1,
        ChromeExtension = 2,
        FirefoxExtension = 3,
        OperaExtension = 4,
        EdgeExtension = 5,
        WindowsDesktop = 6,
        MacOsDesktop = 7,
        LinuxDesktop = 8,
        ChromeBrowser = 9,
        FirefoxBrowser = 10,
        OperaBrowser = 11,
        EdgeBrowser = 12,
        IEBrowser = 13,
        UnknownBrowser = 14,
        AndroidAmazon = 15,
        UWP = 16,
        SafariBrowser = 17,
        VivaldiBrowser = 18,
        VivaldiExtension = 19,
        SafariExtension = 20,
        SDK = 21,
        Server = 22,
        WindowsCLI = 23,
        MacOsCLI = 24,
        LinuxCLI = 25,
        DuckDuckGoBrowser = 26,
        DuckDuckGoExtension = 27,
    };

    enum class ClientType {
        Web,
        Browser,
        Desktop,
        Mobile,
        Cli,
        DirectoryConnector,
    };

    enum class NotificationType : uint8_t {
        SyncCipherUpdate = 0,
        SyncCipherCreate = 1,
        SyncLoginDelete = 2,
        SyncFolderDelete = 3,
        SyncCiphers = 4,

        SyncVault = 5,
        SyncOrgKeys = 6,
        SyncFolderCreate = 7,
        SyncFolderUpdate = 8,
        SyncCipherDelete = 9,
        SyncSettings = 10,

        LogOut = 11,

        SyncSendCreate = 12,
        SyncSendUpdate = 13,
        SyncSendDelete = 14,

        AuthRequest = 15,
        AuthRequestResponse = 16,

        SyncOrganizations = 17,
        SyncOrganizationStatusChanged = 18,
        SyncOrganizationCollectionSettingChanged = 19,
        Notification = 20,
        NotificationStatus = 21,

        RefreshSecurityTasks = 22,

        OrganizationBankAccountVerified = 23,
        ProviderBankAccountVerified = 24,

        SyncPolicy = 25,
        AutoConfirmMember = 26,

        PremiumStatusChanged = 27,
    };

    enum class TwoFactorProviderType : uint8_t {
        Authenticator = 0,
        Email = 1,
        Duo = 2,
        Yubikey = 3,
        U2f = 4,
        Remember = 5,
        OrganizationDuo = 6,
        WebAuthn = 7,
        RecoveryCode = 8,
    };

    constexpr std::string toString(ClientType type) {
        switch (type) {
            case ClientType::Web: 
                return "web";
            case ClientType::Browser: 
                return "browser";
            case ClientType::Desktop: 
                return "desktop";
            case ClientType::Mobile: 
                return "mobile";
            case ClientType::Cli: 
                return "cli";
            case ClientType::DirectoryConnector: 
                return "connector";
            default:
                return "";
        }

        return "";
    }

    constexpr const std::string bitwarden_version = BW_VERSION;
    inline const std::string bitwarden_client = toString(BW_CLIENT);
    inline const std::string bitwarden_device_type = std::to_string(static_cast<unsigned>(BW_DEVICE_TYPE));
    constexpr const std::string bitwarden_device_name = BW_DEVICE_NAME;
}