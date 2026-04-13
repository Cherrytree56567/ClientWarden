#include <iostream>
#include "Vault/Vault.h"
#include "Vault/LoginItem/LoginItem.h"

int main() {
    Vault vault;

    std::string password = "";
    std::string email = "";

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

    LoginItem login(vault);
    std::string Name = "TestLogin";
    std::string Username = "TesterPassword";
    std::string Password = "TesterPassword";
    std::string TOTP = "JS78TYH688G67G78";
    std::string Notes = "Cool Notes ig";
    std::string Website = "exam.com";
    std::string FieldName = "Cool";
    std::string FieldVal = "true";
    login.SetName(Name)
         .SetUsername(Username)
         .SetPassword(Password)
         .SetTotp(TOTP)
         .SetNotes(Notes)
         .AddField(CustomFieldType::Checkbox, FieldName, FieldVal)
         .AddWebsite(Website)
         .Commit();
}