#include "Vault.h"

std::string Vault::b64Encode(const std::vector<uint8_t>& data) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new(BIO_s_mem());
    BIO_push(b64, mem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, data.data(), data.size());
    BIO_flush(b64);

    BUF_MEM* buf;
    BIO_get_mem_ptr(b64, &buf);
    std::string result(buf->data, buf->length);
    BIO_free_all(b64);
    return result;
}

std::vector<uint8_t> Vault::b64Decode(const std::string& data) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new_mem_buf(data.data(), data.size());
    BIO_push(b64, mem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    std::vector<uint8_t> result(data.size());
    int len = BIO_read(b64, result.data(), result.size());
    result.resize(len);
    BIO_free_all(b64);
    return result;
}

std::time_t Vault::BitwardenTime(std::string time) {
    std::tm tmStruct = {};
    double fractional = 0.0;

    std::istringstream ss(time);

    ss >> std::get_time(&tmStruct, "%Y-%m-%dT%H:%M:%S");
    if (ss.fail()) {
        spdlog::info("Failed to parse date-time: {}", time);
        throw std::runtime_error("Failed to parse date-time");
    }

    if (ss.peek() == '.') {
        ss.get();
        std::string fracStr;
        while (isdigit(ss.peek())) {
            fracStr += static_cast<char>(ss.get());
        }
        if (!fracStr.empty()) {
            fractional = std::stod("0." + fracStr);
        }
    }

    if (ss.peek() == 'Z') ss.get();

    std::time_t t = _mkgmtime(&tmStruct);

    t += static_cast<time_t>(fractional);

    return t;
}