#pragma once
#include <string>
#include <vector>
#include <nlohmann/json.hpp>
#include "../GenericItem/GenericItem.h"

namespace ClientWarden {
    class SSHKeyItem : public GenericItemImpl<SSHKeyItem> {
    public:
        SSHKeyItem(Vault& vault, std::string uuid); // Existing Item
        SSHKeyItem(Vault& vault); // New Item

        SSHKeyItem* SetFingerprint(std::string& fingerprint);
        SSHKeyItem* SetPrivateKey(std::string& privateKey);
        SSHKeyItem* SetPublicKey(std::string& publicKey);

        SSHKeyItem* Duplicate(std::string& id);

        SSHKeyItem* GetFingerprint(std::string& fingerprint);
        SSHKeyItem* GetPrivateKey(std::string& privateKey);
        SSHKeyItem* GetPublicKey(std::string& publicKey);
        SSHKeyItem* GetType(CipherType& val) override;
    private:
        inline static std::shared_ptr<spdlog::logger> l_logger = nullptr;
    };
}