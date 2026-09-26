#pragma once
#include <map>
#include <string>
#include <expected>
#include <keychain.h>
#include <botan/secmem.h>
#include "clientwarden.h"

namespace clientwarden::vault {
    /**
     * @brief Used to specify the biometric unlock type.
     * @param Biometric Only Face ID/Fingerprint Biometric is allowed.
     * @param Password Only Device Password or Face ID/Fingerprint is allowed.
     * @param None Biometric Unlock has not been setup.
     */
    enum class UnlockType {
        Biometric,
        Password,
        None
    };

    /**
     * @brief Used to specify the type of auto lock. All of these use a delay.
     * @param Timer Auto Lock after a certain period of time.
     * @param AppBackgrounded Auto Lock after a certain period of the app losing focus.
     * @param Sleep Auto Lock after a certain period of the device going to sleep.
     * @param None Don't use Auto Lock.
     */
    enum class AutoLockType {
        Timer,
        AppBackgrounded,
        Sleep,
        None
    };
   
    /**
     * @brief Used to specify the type of UI theme used.
     */
    enum class Theme {
        Light,
        Dark,
        Auto
    };

    /**
     * @brief Used to specify the type of Sync Method.
     * @param Classic Classic normal vault sync. Shouldn't be used. Uses m_sync_delay.
     * @param WebSocket Newer, recommended sync method. Doesn't use m_sync_delay.
     */
    enum class SyncMethod {
        Classic,
        WebSocket,
        None
    };

    /**
     * @brief Used to specify the type of error when setting or getting a setting.
     * @param GenericError A generic error
     * @param NotFound Keychain key not found
     * @param Unavailable Keychain not available
     * @param KeychainError Error with Keychain service
     * @param AccessDenied No Access to selected key in Keychain
     * @param Unknown Unknown error
     */
    enum class SettingsError {
        GenericError,
        NotFound, 
        Unavailable,
        KeychainError,
        AccessDenied,
        Unknown
    };

    /**
     * @brief Holds values to define Security Values for Keychain
     * @param Biometric Value can only be accessable by the App via Biometric Auth
     * @param Password Value can only be accessable by the App via Device Password Auth
     * @param Sensitive Value can be accessable by the App with no Auth
     * @param Secure Value can be accessable by the App with no Auth and is cached in memory
     */
    enum class KeychainSecurity {
        Biometric,
        Password,
        Sensitive,
        Secure
    };

    /**
     * @brief Used to store various settings
     * @note Unlike other classes, Settings will not be derived
     */
    class Settings {
    public:
        Settings(ItemId uuid);
        virtual ~Settings() = default;

        bool canScreenshot();
        void allowScreenshot(bool value);

        int getAutoLockDelay();
        AutoLockType getAutoLockType();
        void setAutoLock(AutoLockType type, int delay);

        int getClipboardDelay();
        void setClipboardDelay(int delay);

        Theme getTheme();
        void setTheme(Theme theme);

        SyncMethod getSyncMethod();
        void setSyncMethod(SyncMethod method);

        int getSyncDelay();
        void setSyncDelay(int sync_delay);

        UnlockType getUnlockType();
        std::expected<AuthKeys, SettingsError> getBiometricKeys();
        std::expected<void, SettingsError> removeBiometricUnlock();
        std::expected<void, SettingsError> enableBiometricUnlock(UnlockType type, const AuthKeys& keys);

        std::expected<void, SettingsError> keychainSet(KeychainSecurity security, 
            const std::string& name, const Botan::secure_vector<uint8_t>& value);
        std::expected<Botan::secure_vector<uint8_t>, SettingsError> keychainGet(const std::string& name);
        std::expected<void, SettingsError> keychainClear(const std::string& name);

    protected:
        /**
         * @brief Holds vars here instead of re-getting them bc of performance concerns.
         * 
         * @note Everything should be held in keychain, bc Keychain is a secure place that prevents
         * tampering with important Vault Settings.
         */
        bool m_can_screenshot;
        int m_autolock_delay;
        AutoLockType m_autolock;
        UnlockType m_bio_unlock;
        int m_clipboard_delay;
        Theme m_theme;
        SyncMethod m_sync;
        int m_sync_delay;
        
        ItemId m_uuid;
    
    private:
        /**
         * @brief Keychain cache is used to store `Secure` items that arent sensitive but shouldn't
         * be tampered with. Since these arent sensitive, we can cache them for easier access.
         */
        std::map<std::string, Botan::secure_vector<uint8_t>> m_keychain_cache_;
    };
}