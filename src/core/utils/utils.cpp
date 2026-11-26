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
    
    std::string s_getCurrentTime(int additional_time) {
        std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
        std::chrono::time_point<std::chrono::system_clock, std::chrono::seconds> now_seconds = 
            std::chrono::time_point_cast<std::chrono::seconds>(now);
        long long ms = 
            std::chrono::duration_cast<std::chrono::milliseconds>(now - now_seconds).count();

        std::time_t current_time = std::chrono::system_clock::to_time_t(now_seconds) + 
            additional_time;
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
    
    Botan::secure_vector<uint8_t> getCurrentTime(int additional_time) {
        std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
        std::chrono::time_point<std::chrono::system_clock, std::chrono::seconds> now_seconds = 
            std::chrono::time_point_cast<std::chrono::seconds>(now);
        long long ms = 
            std::chrono::duration_cast<std::chrono::milliseconds>(now - now_seconds).count();

        std::time_t current_time = std::chrono::system_clock::to_time_t(now_seconds) + 
            additional_time;
        std::tm utc_tm = *gmtime(&current_time);

        std::ostringstream result;
        result << std::put_time(&utc_tm, "%Y-%m-%dT%H:%M:%S");
        result << "." << std::setfill('0') << std::setw(2) << (ms / 10);
        result << "Z";

        return getSecureVector(result.str());
    }
    
    ItemId getUniqueId() {
        static thread_local boost::uuids::random_generator boost_gen;

        return boost::uuids::to_string(boost_gen());
    }
    
    Botan::secure_vector<uint8_t> getSecureVector(const char* value) {
        const uint8_t* p_value = reinterpret_cast<const uint8_t*>(value);

        return std::move(Botan::secure_vector<uint8_t>(p_value, p_value + std::strlen(value)));
    }
    
    Botan::secure_vector<uint8_t> getSecureVector(std::string value) {
        return std::move(Botan::secure_vector<uint8_t>(value.begin(), value.end()));
    }
    
    Botan::secure_vector<uint8_t> getSecureVector(int value) {
        Botan::secure_vector<uint8_t> result(16);
        char* c_result = reinterpret_cast<char*>(result.data());

        std::to_chars_result res = std::to_chars(c_result, c_result + result.size(), value);
        if (res.ec != std::errc{}) {
            return {};
        }

        result.resize(static_cast<size_t>(res.ptr - c_result));
        return result;
    }
    
    Botan::secure_vector<uint8_t> getSecureVector(Timestamp time) {
        std::string result = std::format("{:%FT%T}Z", 
            std::chrono::floor<std::chrono::milliseconds>(time));

        return Botan::secure_vector<uint8_t>(result.begin(), result.end());
    }
    
    int getInteger(const Botan::secure_vector<uint8_t>& value, int fallback) {
        int result = fallback;
        const char* c_value = reinterpret_cast<const char*>(value.data());

        std::from_chars_result res = std::from_chars(c_value, c_value + value.size(), result);
        if (res.ec != std::errc{} || res.ptr != c_value + value.size()) {
            return fallback;
        }

        return result;
    }
    
    std::string getString(const Botan::secure_vector<uint8_t>& value) {
        return std::move(std::string(value.begin(), value.end()));
    }
    
    std::string getString(Timestamp time) {
        return std::format("{:%FT%T}Z", std::chrono::floor<std::chrono::milliseconds>(time));
    }
    
    int getInt(const std::string& value, int fallback) {
        int result = fallback;

        std::from_chars_result res = std::from_chars(value.data(), value.data() + value.size(), 
            result);
        
        if (res.ec != std::errc{} || res.ptr != value.data() + value.size()) {
            return fallback;
        }

        return result;
    }

    Botan::secure_vector<uint8_t>& discardBuffer() {
        static thread_local Botan::secure_vector<uint8_t> buffer;
        return buffer;
    }
}