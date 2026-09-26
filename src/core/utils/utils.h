#pragma once
#include <string>
#include <botan/secmem.h>
#include "clientwarden.h"

namespace clientwarden::utils {
    /**
     * @brief Base64 Encodes the data.
     */
    Botan::secure_vector<uint8_t> b64Encode(const Botan::secure_vector<uint8_t>& data);
    /**
     * @brief Base64 Decodes the data.
     */
    Botan::secure_vector<uint8_t> b64Decode(const Botan::secure_vector<uint8_t>& data);
    /**
     * @brief Converts ISO 8601 time to std::time_t.
     */
    std::time_t getTime(std::string time);
    /**
     * @brief Converts the current time to std::string + additional time.
     */
    std::string getCurrentTime(int additionalTime = 0);
    /**
     * @brief Generates a Unique Id.
     */
    ItemId getUniqueId();
    /**
     * @brief Converts a const char* to a Botan Secure Vector.
     */
    Botan::secure_vector<uint8_t> getSecureVector(const char* value);
    /**
     * @brief Converts an integer to a string Botan Secure Vector.
     */
    Botan::secure_vector<uint8_t> getSecureVector(int value);
    /**
     * @brief Converts a Botan Secure Vector String to an Int.
     */
    int getInteger(const Botan::secure_vector<uint8_t>& value);
}