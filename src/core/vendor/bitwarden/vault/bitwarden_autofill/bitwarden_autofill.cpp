#include "bitwarden_autofill.h"

namespace clientwarden::vendor::bitwarden::vault {
    BitwardenAutoFill::BitwardenAutoFill(std::shared_ptr<Runtime> runtime, 
        std::shared_ptr<Orchestrator> orchestrator) : AutoFill(runtime, orchestrator) {

    }

    std::expected<PasskeyResult, AutoFillError> BitwardenAutoFill::createPasskey(ItemId item_id, 
        const Botan::secure_vector<uint8_t>& relying_party_identifier, 
        const Botan::secure_vector<uint8_t>& user_name, 
        const Botan::secure_vector<uint8_t>& user_handle, 
        const Botan::secure_vector<uint8_t>& client_data_hash) {
        std::expected<nlohmann::json, RuntimeError> item_err = 
            m_runtime->getItem(item_id);
        
        if (!item_err.has_value()) {
            return std::unexpected(AutoFillError::RuntimeError);
        }

        nlohmann::json item_value = item_err.value();

        if (!item_value.contains("type") || !item_value["type"].is_number() ||
            item_value["type"] != 1 || !item_value.contains("login") || 
            !item_value["login"].is_object()) {
            return std::unexpected(AutoFillError::InvalidItem);
        }
        
        Botan::secure_vector<uint8_t> counter;
        std::string creation_date;
        Botan::secure_vector<uint8_t> credential_id;
        Botan::secure_vector<uint8_t> discoverable;
        Botan::secure_vector<uint8_t> key_algo;
        Botan::secure_vector<uint8_t> key_curve;
        Botan::secure_vector<uint8_t> key_type;
        Botan::secure_vector<uint8_t> key_value;
        Botan::secure_vector<uint8_t> relying_party_name;
        Botan::secure_vector<uint8_t> user_display_name;

        nlohmann::json fido_cred;
        fido_cred["counter"] = utils::getString(counter);
        fido_cred["creationDate"] = creation_date;
        fido_cred["credentialId"] = utils::getString(credential_id);
        fido_cred["discoverable"] = utils::getString(discoverable);
        fido_cred["keyAlgorithm"] = utils::getString(key_algo);
        fido_cred["keyCurve"] = utils::getString(key_curve);
        fido_cred["keyType"] = utils::getString(key_type);
        fido_cred["keyValue"] = utils::getString(key_value);
        fido_cred["response"] = nullptr;
        fido_cred["rpId"] = utils::getString(relying_party_identifier);
        fido_cred["rpName"] = utils::getString(relying_party_name);
        fido_cred["userDisplayName"] = utils::getString(user_display_name);
        fido_cred["userHandle"] = utils::getString(user_handle);
        fido_cred["userName"] = utils::getString(user_name);

        if (!item_type["login"].contains("fido2Credentials") || 
            !item_type["login"]["fido2Credentials"].is_array()) {
            item_type["login"]["fido2Credentials"] = nlohmann::json::array();
        }

        item_type["login"]["fido2Credentials"].push_back(fido_cred);
    }

    PasskeyInfo BitwardenAutoFill::getPasskey(ItemId uuid) {

    }

    Vendor BitwardenAutoFill::getVendor() {
        
    }
}