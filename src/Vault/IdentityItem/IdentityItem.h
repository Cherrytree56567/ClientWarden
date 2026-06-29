#pragma once
#include <string>
#include <vector>
#include <nlohmann/json.hpp>
#include "../CommonVault.h"
#include "../VaultUtils/VaultUtils.h"
#include "../Vault.h"
#include "../GenericItem/GenericItem.h"

namespace ClientWarden::Vault {
    class IdentityItem : public GenericItem {
    public:
        IdentityItem(Vault& vault, std::string uuid); // Existing Item
        IdentityItem(Vault& vault); // New Item

        IdentityItem* SetName(std::string& name) override;
        IdentityItem* SetAddress1(std::string& address1);
        IdentityItem* SetAddress2(std::string& address2);
        IdentityItem* SetAddress3(std::string& address3);
        IdentityItem* SetCity(std::string& city);
        IdentityItem* SetCompany(std::string& company);
        IdentityItem* SetCountry(std::string& country);
        IdentityItem* SetEmail(std::string& email);
        IdentityItem* SetFirstName(std::string& firstName);
        IdentityItem* SetLastName(std::string& lastName);
        IdentityItem* SetLicenceNumber(std::string& licenseNumber);
        IdentityItem* SetMiddleName(std::string& middleName);
        IdentityItem* SetPassportNumber(std::string& passportNumber);
        IdentityItem* SetPhone(std::string& phone);
        IdentityItem* SetPostalCode(std::string& postalCode);
        IdentityItem* SetSSN(std::string& ssn);
        IdentityItem* SetState(std::string& state);
        IdentityItem* SetTitle(std::string& title);
        IdentityItem* SetUsername(std::string& username);
        IdentityItem* SetNotes(std::string& notes) override;
        IdentityItem* SetFolder(std::string folder) override;
        IdentityItem* RemoveFolder() override;
        IdentityItem* AddField(CustomFieldType field, std::string& name, std::string& value) override;
        IdentityItem* RemoveField(std::string& name) override;

        IdentityItem* Duplicate(std::string& id);

        IdentityItem* GetName(std::string& name) override;
        IdentityItem* GetAddress1(std::string& address1);
        IdentityItem* GetAddress2(std::string& address2);
        IdentityItem* GetAddress3(std::string& address3);
        IdentityItem* GetCity(std::string& city);
        IdentityItem* GetCompany(std::string& company);
        IdentityItem* GetCountry(std::string& country);
        IdentityItem* GetEmail(std::string& email);
        IdentityItem* GetFirstName(std::string& firstName);
        IdentityItem* GetLastName(std::string& lastName);
        IdentityItem* GetLicenceNumber(std::string& licenseNumber);
        IdentityItem* GetMiddleName(std::string& middleName);
        IdentityItem* GetPassportNumber(std::string& passportNumber);
        IdentityItem* GetPhone(std::string& phone);
        IdentityItem* GetPostalCode(std::string& postalCode);
        IdentityItem* GetSSN(std::string& ssn);
        IdentityItem* GetState(std::string& state);
        IdentityItem* GetTitle(std::string& title);
        IdentityItem* GetUsername(std::string& username);
        IdentityItem* GetNotes(std::string& notes) override;
        IdentityItem* GetFolder(std::string& folder) override;
        IdentityItem* GetFields(std::vector<std::tuple<CustomFieldType, std::string, std::string>>& value) override;
        IdentityItem* GetId(std::string& value) override;
        
        IdentityItem* AddAttachment(std::string& name, std::string& content, std::string& id, std::function<void(float)> onProgress = nullptr) override;
        IdentityItem* GetAttachmentIDs(std::vector<std::string>& ids) override;
        IdentityItem* GetAttachmentName(std::string id, std::string& name) override;
        IdentityItem* GetAttachment(std::string id, std::string& content, std::function<void(float)> onProgress = nullptr) override;
        IdentityItem* RemoveAttachment(std::string id) override;
        
        IdentityItem* SetFavorite(bool val) override;
        IdentityItem* SetReprompt(bool val) override;
        IdentityItem* GetFavorite(bool& val) override;
        IdentityItem* GetReprompt(bool& val) override;
    private:
        inline static std::shared_ptr<spdlog::logger> l_logger = nullptr;
    };
}