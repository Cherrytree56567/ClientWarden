#pragma once
#include <memory>
#include <vector>
#include <botan/secmem.h>
#include "../runtime/runtime.h"
#include "clientwarden.h"

namespace clientwarden::vault {
    /**
     * @brief Holds the data when using an existing Passkey to Authenticate.
     */
    struct PasskeyInfo {
        Botan::secure_vector<uint8_t> user_handle;
        Botan::secure_vector<uint8_t> signature;
        Botan::secure_vector<uint8_t> authenticator_data;
        Botan::secure_vector<uint8_t> credential_id;
    };

    /**
     * @brief Holds the data returned when generating a passkey.
     */
    struct PasskeyResult {
        Botan::secure_vector<uint8_t> credential_id;
        Botan::secure_vector<uint8_t> attestation_object;
    };

    enum class AutoFillError {
        RuntimeError,
        CryptoError,
        NetworkError,
        OrchestratorError,
        InvalidParams,
        InvalidItem,
        Unknown,
        Success
    };

    class AutoFill {
    public:
        AutoFill(std::shared_ptr<Runtime> runtime, std::shared_ptr<Orchestrator> orchestrator);
        virtual ~AutoFill() = default;
        
        /**
         * @brief Creates and stores a Passkey for the provided relying party.
         */
        virtual std::expected<PasskeyResult, AutoFillError> createPasskey(ItemId item_id,
            const Botan::secure_vector<uint8_t>& relying_party_identifier, 
            const Botan::secure_vector<uint8_t>& user_name, 
            const Botan::secure_vector<uint8_t>& user_handle, 
            const Botan::secure_vector<uint8_t>& client_data_hash) = 0;
        /**
         * @brief Get Passkey Info from the Login that matches the provided ItemId.
         */
        virtual std::expected<PasskeyInfo, AutoFillError> getPasskey(ItemId uuid) = 0;

        /**
         * @brief Returns the Vendor.
         */
        virtual Vendor getVendor() = 0;
    protected:
        std::shared_ptr<Runtime> m_runtime;
        std::shared_ptr<Orchestrator> m_orchestrator;
    };
}