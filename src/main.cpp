#include <iostream>
#include "Vault/Vault.h"

int main() {
    Vault vault;

    // TODO: ADD YOUR EMAIL AND PASSWORD HERE TO BUILD AS AN STD::STRING

    if (!vault.login(password)) {
        Errors result = vault.FirstTimeLogin(password, email);

        if (result == Errors::NeedsOTP) {
            std::string otp;
            std::cout << "OTP: ";
            std::cin >> otp;
            vault.FirstTimeLoginOTP(otp);
        } else if (result == Errors::NeedsNewDevice) {
            std::string newDevice;
            std::cout << "New Device Code: ";
            std::cin >> newDevice;
            vault.FirstTimeLoginDeviceVerify(newDevice);
        }
    }

    vault.sync();
}