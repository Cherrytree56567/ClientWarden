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
        std::istringstream s_time{ time };
        date::sys_time<std::chrono::nanoseconds> sys_time;

        s_time >> date::parse("%FT%TZ", sys_time);

        if (s_time.fail()) {
            return Timestamp{ };
        }
        
        return std::chrono::time_point_cast<Timestamp::duration>(sys_time);
    }
    
    std::string s_getCurrentTime(int additional_time = 0) {
        std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
        std::chrono::time_point<std::chrono::system_clock, std::chrono::seconds> now_seconds = 
            std::chrono::time_point_cast<std::chrono::seconds>(now);
        long long ms = 
            std::chrono::duration_cast<std::chrono::milliseconds>(now - now_seconds).count();

        std::time_t current_time = std::chrono::system_clock::to_time_t(now_seconds) + 
            additionalTime;
        std::tm utc_tm = *gmtime(&current_time);

        std::ostringstream result;
        result << std::put_time(&utc_tm, "%Y-%m-%dT%H:%M:%S");
        result << "." << std::setfill('0') << std::setw(2) << (ms / 10);
        result << "Z";

        return result.str();
    }
    
    Timestamp getTime(Botan::secure_vector<uint8_t> time) {
        std::istringstream s_time{ std::string(time.begin(), time.end()) };
        date::sys_time<std::chrono::nanoseconds> sys_time;

        s_time >> date::parse("%FT%TZ", sys_time);

        if (s_time.fail()) {
            return Timestamp{ };
        }
        
        return std::chrono::time_point_cast<Timestamp::duration>(sys_time);
    }
    
    Botan::secure_vector<uint8_t> getCurrentTime(int additional_time = 0) {
        std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
        std::chrono::time_point<std::chrono::system_clock, std::chrono::seconds> now_seconds = 
            std::chrono::time_point_cast<std::chrono::seconds>(now);
        long long ms = 
            std::chrono::duration_cast<std::chrono::milliseconds>(now - now_seconds).count();

        std::time_t current_time = std::chrono::system_clock::to_time_t(now_seconds) + 
            additionalTime;
        std::tm utc_tm = *gmtime(&current_time);

        std::ostringstream result;
        result << std::put_time(&utc_tm, "%Y-%m-%dT%H:%M:%S");
        result << "." << std::setfill('0') << std::setw(2) << (ms / 10);
        result << "Z";

        return getSecureVector(result.str());
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