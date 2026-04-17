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
#include "UI/UI.h"

int main() {
    ClientWarden::Vault::Vault vault;

    if (!vault.hasStoredSession()) {
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
        vault.Unlock(password);
    }

    vault.startRefreshThread();
    vault.Sync();

    /*ClientWarden::UI::UI ui;
    ui.Run();*/
}