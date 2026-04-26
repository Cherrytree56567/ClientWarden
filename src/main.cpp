#include <iostream>
#include "Vault/Vault.h"
#include "Vault/LoginItem/LoginItem.h"
#include "Vault/CardItem/CardItem.h"
#include "Vault/NoteItem/NoteItem.h"
#include "Vault/IdentityItem/IdentityItem.h"
#include "Vault/SSHKeyItem/SSHKeyItem.h"
#include "Vault/Folder/Folder.h"
#include "Vault/CipherQuery/CipherQuery.h"
#include "Vault/PasswordGenerator/PasswordGenerator.h"

int main() {
    ClientWarden::Vault::Vault vault;

    std::string password;
    std::string email;

    //ClientWarden::UI::UI ui;
    //ui.Start();

    if (!vault.hasStoredSession()) {
        //ui.login(email, password);
        ClientWarden::Vault::AuthState result = vault.Login(email, password);

        if (result == ClientWarden::Vault::AuthState::NeedsTOTP) {
            std::string otp;
            std::cout << "OTP: ";
            std::cin >> otp;
            vault.submitTOTP(otp);
        } else if (result == ClientWarden::Vault::AuthState::NeedsEmailVerification) {
            std::string newDevice;
            std::cout << "New Device Code: ";
            std::cin >> newDevice;
            vault.submitDeviceVerify(newDevice);
        }

        if (vault.postLogin() != ClientWarden::Vault::NetworkState::Success) {
            spdlog::info("Failed to login");
        }
    } else {
        //ui.unlock(password, vault.GetName());
        vault.Unlock(password);
    }

    vault.startRefreshThread();
    vault.Sync();

    std::string name = "Test";
    ClientWarden::Vault::TOTPCode code;

    ClientWarden::Vault::LoginItem login(vault, "96832e0c-1eeb-4aa4-8e04-0b37693d4302");
    login.GetTotp(code).Close();

    spdlog::info("Code: {}", code.code);

    vault.stopRefreshThread();
    vault.Lock();
    //ui.Stop();

    while(true) {}
}