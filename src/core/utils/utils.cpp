#include "utils.h"

namespace clientwarden::utils {
    Botan::secure_vector<uint8_t> b64Encode(const Botan::secure_vector<uint8_t>& data) {
        Botan::secure_vector<uint8_t> result(Botan::base64_encode_max_output(data.size()));

        size_t size = 0;
        const size_t written = Botan::base64_encode(
            reinterpret_cast<char*>(result.data()), data.data(), data.size(), size, true);

        result.resize(written);

        return result;
    }

    Botan::secure_vector<uint8_t> b64Decode(const Botan::secure_vector<uint8_t>& data) {
        Botan::secure_vector<uint8_t> result(Botan::base64_decode_max_output(data.size()));

        const size_t written = Botan::base64_decode(
            result.data(), reinterpret_cast<const char*>(data.data()), data.size());

        result.resize(written);
        
        return result;
    }
    
    Botan::secure_vector<uint8_t> b32Encode(const Botan::secure_vector<uint8_t>& data) {
        Botan::secure_vector<uint8_t> result(Botan::base32_encode_max_output(data.size()));

        size_t size = 0;
        const size_t written = Botan::base32_encode(
            reinterpret_cast<char*>(result.data()), data.data(), data.size(), size, true);

        result.resize(written);

        return result;
    }
    
    Botan::secure_vector<uint8_t> b32Decode(const Botan::secure_vector<uint8_t>& data) {
        Botan::secure_vector<uint8_t> result(Botan::base32_decode_max_output(data.size()));

        const size_t written = Botan::base32_decode(
            result.data(), reinterpret_cast<const char*>(data.data()), data.size(), true);

        result.resize(written);
        
        return result;
    }
    
    Timestamp s_getTime(std::string time) {

    }
    
    std::string s_getCurrentTime(int additional_time = 0) {

    }
    
    Timestamp getTime(Botan::secure_vector<uint8_t> time) {

    }
    
    Botan::secure_vector<uint8_t> getCurrentTime(int additional_time = 0) {

    }
    
    ItemId getUniqueId() {

    }
    
    Botan::secure_vector<uint8_t> getSecureVector(const char* value) {

    }
    
    Botan::secure_vector<uint8_t> getSecureVector(std::string value) {

    }
    
    Botan::secure_vector<uint8_t> getSecureVector(int value) {

    }
    
    Botan::secure_vector<uint8_t> getSecureVector(Timestamp time) {

    }
    
    int getInteger(const Botan::secure_vector<uint8_t>& value) {

    }
    
    std::string getString(const Botan::secure_vector<uint8_t>& value) {

    }
    
    std::string getString(Timestamp time) {

    }
    
    int getInt(std::string& value, int fallback) {

    }
}