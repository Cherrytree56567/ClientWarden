#include "settings.h"

namespace clientwarden::vault {
    Settings::Settings(ItemId uuid) : m_uuid(uuid) {
        /**
         * TODO: Initialise all values (m_can_screenshot)
         */
        std::expected<Botan::secure_vector<uint8_t>, SettingsError> result;

        result = keychainGet("allowScreenshot");
        
        if (!result) {
            keychainSet(KeychainSecurity::Secure, "allowScreenshot", getSecureVector("false"));

            m_can_screenshot = false;
        } else {
            if (result.value() == getSecureVector("true")) {
                m_can_screenshot = true;
            } else {
                m_can_screenshot = false;
            }
        }

        result = keychainGet("autoLock");
        
        if (!result) {
            keychainSet(KeychainSecurity::Secure, "autoLock", getSecureVector("noFocus"));

            m_autolock = AutoLockType::AppBackgrounded;
        } else {
            if (result.value() == getSecureVector("timer")) {
                m_autolock = AutoLockType::Timer;
            } else if (result.value() == getSecureVector("noFocus")) {
                m_autolock = AutoLockType::AppBackgrounded;
            } else if (result.value() == getSecureVector("sleep")) {
                m_autolock = AutoLockType::Sleep;
            } else if (result.value() == getSecureVector("none")) {
                m_autolock = AutoLockType::None;
            } else {
                m_autolock = AutoLockType::AppBackgrounded;
            }
        }

        result = keychainGet("autoLockDelay");
        
        if (!result) {
            keychainSet(KeychainSecurity::Secure, "autoLockDelay", getSecureVector(30));

            m_autolock_delay = 30;
        } else {
            std::from_chars_result stoi_res = std::from_chars(
                reinterpret_cast<const char*>(result.value().data()),
                reinterpret_cast<const char*>(result.value().data() + result.value().size()),
                m_autolock_delay
            );

            if (stoi_res.ec != std::errc{}) {
                keychainSet(KeychainSecurity::Secure, "autoLockDelay", getSecureVector(30));

                m_autolock_delay = 30;
            }
        }

        result = keychainGet("clipboardDelay");
        
        if (!result) {
            keychainSet(KeychainSecurity::Secure, "clipboardDelay", getSecureVector(30));

            m_clipboard_delay = 30;
        } else {
            std::from_chars_result stoi_res = std::from_chars(
                reinterpret_cast<const char*>(result.value().data()),
                reinterpret_cast<const char*>(result.value().data() + result.value().size()),
                m_clipboard_delay
            );

            if (stoi_res.ec != std::errc{}) {
                keychainSet(KeychainSecurity::Secure, "clipboardDelay", getSecureVector(30));

                m_clipboard_delay = 30;
            }
        }

        result = keychainGet("theme");
        
        if (!result) {
            keychainSet(KeychainSecurity::Secure, "theme", getSecureVector("auto"));

            m_theme = Theme::Auto;
        } else {
            if (result.value() == getSecureVector("light")) {
                m_theme = Theme::Light;
            } else if (result.value() == getSecureVector("dark")) {
                m_theme = Theme::Dark;
            } else if (result.value() == getSecureVector("auto")) {
                m_theme = Theme::Auto;
            } else {
                m_theme = Theme::Auto;
            }
        }

        result = keychainGet("sync");
        
        if (!result) {
            keychainSet(KeychainSecurity::Secure, "sync", getSecureVector("websocket"));

            m_sync = SyncMethod::WebSocket;
        } else {
            if (result.value() == getSecureVector("classic")) {
                m_sync = SyncMethod::Classic;
            } else if (result.value() == getSecureVector("websocket")) {
                m_sync = SyncMethod::WebSocket;
            } else if (result.value() == getSecureVector("none")) {
                m_sync = SyncMethod::None;
            } else {
                m_sync = SyncMethod::WebSocket;
            }
        }

        result = keychainGet("syncDelay");
        
        if (!result) {
            keychainSet(KeychainSecurity::Secure, "syncDelay", getSecureVector(30));

            m_sync_delay = 30;
        } else {
            std::from_chars_result stoi_res = std::from_chars(
                reinterpret_cast<const char*>(result.value().data()),
                reinterpret_cast<const char*>(result.value().data() + result.value().size()),
                m_sync_delay
            );

            if (stoi_res.ec != std::errc{}) {
                keychainSet(KeychainSecurity::Secure, "syncDelay", getSecureVector(30));

                m_sync_delay = 30;
            }
        }
    }

    bool Settings::canScreenshot() {
        return m_can_screenshot;
    }

    void Settings::allowScreenshot(bool value) {
        std::expected<void, SettingsError> result;
        
        result = keychainSet(KeychainSecurity::Secure, "allowScreenshot", getSecureVector(value ? "true" : "false"));

        if (result) {
            m_can_screenshot = value;
        }
    }

    int Settings::getAutoLockDelay() {
        return m_autolock_delay;
    }

    AutoLockType Settings::getAutoLockType() {
        return m_autolock;
    }

    void Settings::setAutoLock(AutoLockType type, int delay) {
        std::expected<void, SettingsError> result;

        if (type == AutoLockType::Timer) {
            result = keychainSet(KeychainSecurity::Secure, "autoLock", getSecureVector("timer"));
        } else if (type == AutoLockType::AppBackgrounded) {
            result = keychainSet(KeychainSecurity::Secure, "autoLock", getSecureVector("noFocus"));
        } else if (type == AutoLockType::Sleep) {
            result = keychainSet(KeychainSecurity::Secure, "autoLock", getSecureVector("sleep"));
        } else if (type == AutoLockType::None) {
            result = keychainSet(KeychainSecurity::Secure, "autoLock", getSecureVector("none"));
        } else {
            return;
        }

        if (result) {
            m_autolock = type;
        }

        result = keychainSet(KeychainSecurity::Secure, "autoLockDelay", getSecureVector(delay));

        if (result) {
            m_autolock_delay = delay;
        }
    }

    int Settings::getClipboardDelay() {
        return m_clipboard_delay;
    }

    void Settings::setClipboardDelay(int delay) {
        std::expected<void, SettingsError> result;

        result = keychainSet(KeychainSecurity::Secure, "clipboardDelay", getSecureVector(delay));

        if (result) {
            m_clipboard_delay = delay;
        }
    }

    Theme Settings::getTheme() {
        return m_theme;
    }

    void Settings::setTheme(Theme theme) {
        std::expected<void, SettingsError> result;

        if (theme == Theme::Light) {
            result = keychainSet(KeychainSecurity::Secure, "theme", getSecureVector("light"));
        } else if (theme == Theme::Dark) {
            result = keychainSet(KeychainSecurity::Secure, "theme", getSecureVector("dark"));
        } else if (theme == Theme::Auto) {
            result = keychainSet(KeychainSecurity::Secure, "theme", getSecureVector("auto"));
        } else {
            return;
        }

        if (result) {
            m_theme = theme;
        }
    }

    SyncMethod Settings::getSyncMethod() {
        return m_sync;
    }

    void Settings::setSyncMethod(SyncMethod method) {
        std::expected<void, SettingsError> result;

        if (method == SyncMethod::Classic) {
            result = keychainSet(KeychainSecurity::Secure, "sync", getSecureVector("classic"));
        } else if (method == SyncMethod::WebSocket) {
            result = keychainSet(KeychainSecurity::Secure, "sync", getSecureVector("websocket"));
        } else if (method == SyncMethod::None) {
            result = keychainSet(KeychainSecurity::Secure, "sync", getSecureVector("none"));
        } else {
            return;
        }

        if (result) {
            m_sync = method;
        }
    }

    int Settings::getSyncDelay() {
        return m_sync_delay;
    }

    void Settings::setSyncDelay(int sync_delay) {
        std::expected<void, SettingsError> result;
        
        result = keychainSet(KeychainSecurity::Secure, "syncDelay", getSecureVector(sync_delay));

        if (result) {
            m_sync_delay = sync_delay;
        }
    }

    UnlockType Settings::getUnlockType() {
        return m_bio_unlock;
    }

    std::expected<AuthKeys, SettingsError> Settings::getBiometricKeys() {
        std::expected<Botan::secure_vector<uint8_t>, SettingsError> result = keychainGet("bio_keys");
        
        if (!result) {
            return std::unexpected(result.error());
        }

        Botan::secure_vector<uint8_t> encoded_keys = result.value();

        Botan::secure_vector<uint8_t>::iterator encoded_iterator = 
            std::find(encoded_keys.begin(), encoded_keys.end(), ',');
        
        if (encoded_iterator == encoded_keys.end()) {
            return std::unexpected(SettingsError::GenericError);
        }

        Botan::secure_vector<uint8_t> encoded_key(encoded_keys.begin(), encoded_iterator);
        Botan::secure_vector<uint8_t> encoded_hash(encoded_iterator + 1, encoded_keys.end());

        encoded_keys.clear();

        AuthKeys keys;
        keys.internal_key = utils::b64Decode(encoded_key);
        keys.master_password_hash = utils::b64Decode(encoded_hash);

        encoded_key.clear();
        encoded_hash.clear();

        return keys;
    }

    std::expected<void, SettingsError> Settings::removeBiometricUnlock() {
        return keychainClear("bio_keys");
    }

    std::expected<void, SettingsError> Settings::enableBiometricUnlock(UnlockType type, const AuthKeys& keys) {
        if (type == UnlockType::None) {
            return removeBiometricUnlock();
        }

        std::expected<void, SettingsError> result;

        Botan::secure_vector<uint8_t> encoded_key = utils::b64Encode(keys.internal_key);
        Botan::secure_vector<uint8_t> encoded_hash = utils::b64Encode(keys.master_password_hash);

        Botan::secure_vector<uint8_t> encoded_keys = encoded_key;
        encoded_keys.push_back(',');
        encoded_keys.insert(encoded_keys.end(), encoded_hash.begin(), encoded_hash.end());

        encoded_key.clear();
        encoded_hash.clear();
        
        result = keychainSet(static_cast<KeychainSecurity>(std::to_underlying(type)), "bio_keys", encoded_keys);

        encoded_keys.clear();

        return result;
    }

    std::expected<void, SettingsError> Settings::keychainSet(KeychainSecurity security, 
        const std::string& name, const Botan::secure_vector<uint8_t>& value) {
        keychain::SecurityDetail detail;
        bool cache = false;
        if (security == KeychainSecurity::Biometric) {
            detail = keychain::SecurityDetail::SecureBio;
        } else if (security == KeychainSecurity::Password) {
            detail = keychain::SecurityDetail::Secure;
        } else if (security == KeychainSecurity::Sensitive) {
            detail = keychain::SecurityDetail::NoPassword;
        } else if (security == KeychainSecurity::Secure) {
            cache = true;
            detail = keychain::SecurityDetail::NoPassword;
        }

        keychain::Error error;

        std::string string_value(value.begin(), value.end());

        keychain::setPassword(app_id, m_uuid, name, string_value, error, detail);

        OPENSSL_cleanse(string_value.data(), string_value.size());

        if (error) {
            if (error.type == keychain::ErrorType::GenericError) {
                return std::unexpected(SettingsError::GenericError);
            } else if (error.type == keychain::ErrorType::NotFound) {
                return std::unexpected(SettingsError::NotFound);
            } else if (error.type == keychain::ErrorType::Unavailable) {
                return std::unexpected(SettingsError::Unavailable);
            } else if (error.type == keychain::ErrorType::PasswordTooLong) {
                return std::unexpected(SettingsError::KeychainError);
            } else if (error.type == keychain::ErrorType::AccessDenied) {
                return std::unexpected(SettingsError::AccessDenied);
            } else {
                return std::unexpected(SettingsError::Unknown);
            } 
        }

        if (cache) {
            m_keychain_cache_[name] = value;
        }

        return {};
    }

    std::expected<Botan::secure_vector<uint8_t>, SettingsError> Settings::keychainGet(const std::string& name) {
        if (m_keychain_cache_.contains(name)) {
            return m_keychain_cache_[name];
        }

        keychain::Error error;

        std::string password = keychain::getPassword(app_id, m_uuid, name, error);

        if (error) {
            if (error.type == keychain::ErrorType::GenericError) {
                return std::unexpected(SettingsError::GenericError);
            } else if (error.type == keychain::ErrorType::NotFound) {
                return std::unexpected(SettingsError::NotFound);
            } else if (error.type == keychain::ErrorType::Unavailable) {
                return std::unexpected(SettingsError::Unavailable);
            } else if (error.type == keychain::ErrorType::PasswordTooLong) {
                return std::unexpected(SettingsError::KeychainError);
            } else if (error.type == keychain::ErrorType::AccessDenied) {
                return std::unexpected(SettingsError::AccessDenied);
            } else {
                return std::unexpected(SettingsError::Unknown);
            } 
        }
        
        Botan::secure_vector<uint8_t> result(password.begin(), password.end());

        OPENSSL_cleanse(password.data(), password.size());

        return result;
    }

    std::expected<void, SettingsError> Settings::keychainClear(const std::string& name) {
        if (m_keychain_cache_.contains(name)) {
            m_keychain_cache_.erase(name);
        }

        keychain::Error error;

        keychain::deletePassword(app_id, m_uuid, name, error);

        if (error) {
            if (error.type == keychain::ErrorType::GenericError) {
                return std::unexpected(SettingsError::GenericError);
            } else if (error.type == keychain::ErrorType::NotFound) {
                return std::unexpected(SettingsError::NotFound);
            } else if (error.type == keychain::ErrorType::Unavailable) {
                return std::unexpected(SettingsError::Unavailable);
            } else if (error.type == keychain::ErrorType::PasswordTooLong) {
                return std::unexpected(SettingsError::KeychainError);
            } else if (error.type == keychain::ErrorType::AccessDenied) {
                return std::unexpected(SettingsError::AccessDenied);
            } else {
                return std::unexpected(SettingsError::Unknown);
            } 
        }

        return {};
    }
}