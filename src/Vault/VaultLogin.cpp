#include "Vault.h"

namespace ClientWarden::Vault {
    AuthState Vault::Login(std::string& email, std::string& password) {
        boost::algorithm::to_lower(email);
        if (preLogin(email) != NetworkState::Success) {
            return AuthState::Failed;
        }

        internalKey = makeKey(password, authData["salt"], authData["kdfIterations"]);
        masterPasswordHash = hashedPassword(password, authData["salt"], authData["kdfIterations"]);

        /*
        * Erase the password safely
        */
        OPENSSL_cleanse(password.data(), password.size());
        password.clear();

        return getToken();
    }

    AuthState Vault::submitTOTP(std::string& totp) {
        return getTokenWTotp(totp);
    }

    AuthState Vault::submitDeviceVerify(std::string& code) {
        return getTokenWDeviceVerify(code);
    }

    NetworkState Vault::postLogin() {
        NetworkState hr = Sync();
        if (hr != NetworkState::Success) {
            return hr;
        }

        getMainKeys();
        return NetworkState::Success;
    }

    void Vault::Unlock(std::string& password) {
        internalKey = makeKey(password, authData["salt"], authData["kdfIterations"]);
        masterPasswordHash = hashedPassword(password, authData["salt"], authData["kdfIterations"]);

        /*
        * Erase the password safely
        */
        OPENSSL_cleanse(password.data(), password.size());
        password.clear();

        getMainKeys();
    }

    bool Vault::hasStoredSession() {
        if (!storage.exists("data.json") || !storage.exists("vault.json")) {
            return false;
        }

        loadFiles();

        if (!checkConnectivity()) {
            return true;
        }

        return checkAccessTokenValidity();
    }

    void Vault::loadFiles() {
        authData = nlohmann::json::parse(storage.read("data.json"));
        vaultData = nlohmann::json::parse(storage.read("vault.json"));
    }
}