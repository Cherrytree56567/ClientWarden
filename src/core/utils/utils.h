#pragma once
#include <string>
#include <botan/secmem.h>
#include "clientwarden.h"

namespace clientwarden::utils {
    Botan::secure_vector<uint8_t> b64Encode(const Botan::secure_vector<uint8_t>& data);
    Botan::secure_vector<uint8_t> b64Decode(const Botan::secure_vector<uint8_t>& data);
    std::time_t getTime(std::string time);
    std::string getCurrentTime(int additionalTime = 0);
    ItemId getUniqueId();
    Botan::secure_vector<uint8_t> getSecureVector(const char* value);
    Botan::secure_vector<uint8_t> getSecureVector(int value);
    int getInteger(const Botan::secure_vector<uint8_t>& value);
}