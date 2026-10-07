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
    std::time_t s_getTime(std::string time);
    /**
     * @brief Converts the current time to std::string + additional time.
     */
    std::string s_getCurrentTime(int additional_time = 0);
    /**
     * @brief Converts ISO 8601 time to std::time_t.
     */
    std::time_t getTime(Botan::secure_vector<uint8_t> time);
    /**
     * @brief Converts the current time to std::string + additional time.
     */
    Botan::secure_vector<uint8_t> getCurrentTime(int additional_time = 0);
    /**
     * @brief Generates a Unique Id.
     */
    ItemId getUniqueId();
    /**
     * @brief Converts a const char* to a Botan Secure Vector.
     */
    Botan::secure_vector<uint8_t> getSecureVector(const char* value);
    /**
     * @brief Converts a std::string to Botan Secure Vector.
     */
    Botan::secure_vector<uint8_t> getSecureVector(std::string value);
    /**
     * @brief Converts an integer to a string Botan Secure Vector.
     */
    Botan::secure_vector<uint8_t> getSecureVector(int value);
    /**
     * @brief Converts a Botan Secure Vector String to an Int.
     */
    int getInteger(const Botan::secure_vector<uint8_t>& value);
    /**
     * @brief Converts a Botan Secure Vector String to a String.
     */
    std::string getString(const Botan::secure_vector<uint8_t>& value);
}