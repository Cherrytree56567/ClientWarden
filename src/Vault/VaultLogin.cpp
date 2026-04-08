#include "Vault.h"

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