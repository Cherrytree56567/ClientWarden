#include <iostream>
#include "Vault/Vault.h"

int main() {
    Vault vault;

    std::string password = "S4perM93N877&^A";
    std::string email = "60bn0ip1w@mozmail.com";

    AuthState result = vault.Login(password, email);

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

    //vault.sync();
}