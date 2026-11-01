#pragma once
#include "vault/autofill/autofill.h"

namespace clientwarden::vendor::bitwarden::vault {
    class BitwardenAutoFill : public AutoFill {
    public:
        explicit BitwardenAutoFill(std::shared_ptr<Runtime> runtime, 
            std::shared_ptr<Orchestrator> orchestrator, std::shared_ptr<Crypto> crypto);
        ~BitwardenAutoFill() override = default;

        std::expected<PasskeyResult, AutoFillError> createPasskey(ItemId item_id, 
            const Botan::secure_vector<uint8_t>& relying_party_identifier, 
            const Botan::secure_vector<uint8_t>& user_name, 
            const Botan::secure_vector<uint8_t>& user_handle, 
            const Botan::secure_vector<uint8_t>& client_data_hash) override;
        std::expected<PasskeyInfo, AutoFillError> getPasskey(ItemId uuid) override;

        Vendor getVendor() override;
    };
}