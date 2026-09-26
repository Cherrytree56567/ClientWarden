#pragma once
#include <memory>
#include <vector>
#include <botan/secmem.h>
#include "../runtime/runtime.h"
#include "clientwarden.h"

namespace clientwarden::vault {
    struct PasskeyInfo {
        Botan::secure_vector<uint8_t> user_handle;
        Botan::secure_vector<uint8_t> signature;
        Botan::secure_vector<uint8_t> authenticator_data;
        Botan::secure_vector<uint8_t> credential_id;
    };

    struct PasskeyResult {
        Botan::secure_vector<uint8_t> credential_id;
        Botan::secure_vector<uint8_t> attestation_object;
    };

    class AutoFill {
    public:
        AutoFill(std::shared_ptr<Runtime> runtime);
        virtual ~AutoFill() = default;

        virtual std::vector<ItemId> getLogins(const Botan::secure_vector<uint8_t>& website) = 0;
        virtual Botan::secure_vector<uint8_t> getTitle(ItemId uuid) = 0;
        virtual Botan::secure_vector<uint8_t> getUsername(ItemId uuid) = 0;
        virtual Botan::secure_vector<uint8_t> getPassword(ItemId uuid) = 0;

        virtual std::vector<ItemId> getPasskeys(const Botan::secure_vector<uint8_t>& website) = 0;
        virtual PasskeyResult createPasskey(const Botan::secure_vector<uint8_t>& relying_party_identifier, 
            const Botan::secure_vector<uint8_t>& user_name, 
            const Botan::secure_vector<uint8_t>& user_handle, 
            const Botan::secure_vector<uint8_t>& client_data_hash) = 0;
        virtual PasskeyInfo getPasskey(ItemId uuid) = 0;

        virtual Vendor getVendor() = 0;
    protected:
        std::shared_ptr<Runtime> m_runtime;
    };
}