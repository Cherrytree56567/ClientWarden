#include <iostream>
#include "Vault/Vault.h"
#include "Vault/LoginItem/LoginItem.h"
#include "Vault/CardItem/CardItem.h"
#include "Vault/NoteItem/NoteItem.h"
#include "Vault/IdentityItem/IdentityItem.h"
#include "Vault/SSHKeyItem/SSHKeyItem.h"
#include "Vault/Folder/Folder.h"
#include "Vault/CipherQuery/CipherQuery.h"

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

    ClientWarden::Vault::CipherQuery query(vault);
    std::vector<std::string> ids = query.FilterByUnbinned()
         .FilterByType(ClientWarden::Vault::CipherType::SSHKey)
         .FilterNameByRegex("^(?=.*S)(?=.*i).*")
         .Get();
    
    for (auto& id : ids) {
        ClientWarden::Vault::SSHKeyItem ssh(vault, id);
        std::string name;
        ssh.GetName(name).Close();
        spdlog::info("KEY: {}", name);
    }
}