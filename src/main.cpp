#include <iostream>
#include "Vault/Vault.h"

int main() {
    Vault vault;

    std::string password = "S4perM93N877&^A";
    std::string email = "60bn0ip1w@mozmail.com";

    if (!vault.hasStoredSession()) {
        AuthState result = vault.Login(email, password);

        if (result == AuthState::NeedsTOTP) {
            std::string otp;
            std::cout << "OTP: ";
            std::cin >> otp;
            vault.submitTOTP(otp);
        } else if (result == AuthState::NeedsEmailVerification) {
            std::string newDevice;
            std::cout << "New Device Code: ";
            std::cin >> newDevice;
            vault.submitDeviceVerify(newDevice);
        }

        if (vault.postLogin() != NetworkState::Success) {
            spdlog::info("Failed to login");
        }
    } else {
        vault.Unlock(password);
    }

    vault.startRefreshThread();
    vault.Sync();

    LoginDetails login;
    login.username = "tester@example.com";
    login.password = "ATesterPa55w0rd";
    login.loginName = "Ter";
    login.websites.push_back("example.com");
    login.customFields.push_back({CustomFieldType::Checkbox, "Good", "true"});
    vault.CreateLogin(login);
}