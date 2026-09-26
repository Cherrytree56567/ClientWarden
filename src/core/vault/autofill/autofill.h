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

    class AutoFill {
    public:
        AutoFill(std::shared_ptr<Runtime> runtime);
        virtual ~AutoFill() = default;

        /**
         * @brief Returns an array of ItemId's of LoginItems that match the provided website.
         */
        virtual std::vector<ItemId> getLogins(const Botan::secure_vector<uint8_t>& website) = 0;
        /**
         * @brief Returns the Title of the LoginItem that matches the provided ItemId.
         */
        virtual Botan::secure_vector<uint8_t> getTitle(ItemId uuid) = 0;
        /**
         * @brief Returns the Username of the LoginItem that matches the provided ItemId.
         */
        virtual Botan::secure_vector<uint8_t> getUsername(ItemId uuid) = 0;
        /**
         * @brief Returns the Password of the LoginItem that matches the provided ItemId.
         */
        virtual Botan::secure_vector<uint8_t> getPassword(ItemId uuid) = 0;

        /**
         * @brief Returns an array of ItemId's of LoginItems that contain a Passkey which match the 
         *  provided website.
         */
        virtual std::vector<ItemId> getPasskeys(const Botan::secure_vector<uint8_t>& website) = 0;
        /**
         * @brief Creates and stores a Passkey for the provided relying party.
         */
        virtual PasskeyResult createPasskey(const Botan::secure_vector<uint8_t>& relying_party_identifier, 
            const Botan::secure_vector<uint8_t>& user_name, 
            const Botan::secure_vector<uint8_t>& user_handle, 
            const Botan::secure_vector<uint8_t>& client_data_hash) = 0;
        /**
         * @brief Get Passkey Info from the Login that matches the provided ItemId.
         */
        virtual PasskeyInfo getPasskey(ItemId uuid) = 0;

        /**
         * @brief Returns the Vendor.
         */
        virtual Vendor getVendor() = 0;
    protected:
        std::shared_ptr<Runtime> m_runtime;
    };
}