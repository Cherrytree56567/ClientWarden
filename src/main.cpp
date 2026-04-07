#include <iostream>
#include "Vault/Vault.h"

int main() {
    Vault vault;

    std::string password = "S4perM93N877&^A";
    std::string email = "60bn0ip1w@mozmail.com";

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