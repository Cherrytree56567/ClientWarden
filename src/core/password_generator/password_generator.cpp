#include "password_generator.h"

namespace clientwarden {
    PasswordGenerator::PasswordGenerator() {
        
    }

    PasswordGenerator::~PasswordGenerator() {

    }

    PasswordGenerator& PasswordGenerator::random(int length, bool inc_num, bool inc_sym, 
        bool caps, Botan::secure_vector<uint8_t>& password) {
        password.clear();

        if (length <= 0) {
            return *this;
        }

        std::vector<std::string> chars = alphabets;

        if (caps) {
            chars.insert(chars.end(), alphabetsCaps.begin(), alphabetsCaps.end());
        }
        if (inc_num) {
            chars.insert(chars.end(), numbers.begin(), numbers.end());
        }
        if (inc_sym) {
            chars.insert(chars.end(), symbols.begin(), symbols.end());
        }

        password.resize(length);

        size_t i = 0;
        while (i < static_cast<size_t>(length)) {
            uint8_t value;

            if (RAND_bytes(&value, 1) != 1) {
                logger->error("RAND_bytes failed");
                password.clear();
                return *this;
            }

            if (value >= 256 - (256 % chars.size())) {
                continue;
            }

            password[i++] = chars[value % chars.size()][0];
        }

        return *this;
    }

    PasswordGenerator& PasswordGenerator::memorable(int length, bool cap_first_letter, 
        Botan::secure_vector<uint8_t>& password) {
        password.clear();

        if (length <= 0 || word_list.empty()) {
            return *this;
        }

        for (int i = 0; i < length; i++) {
            uint32_t value;

            while (true) {
                if (RAND_bytes(reinterpret_cast<uint8_t*>(&value), sizeof(value)) != 1) {
                    logger->error("RAND_bytes failed");
                    password.clear();
                    return *this;
                }

                if (value < UINT32_MAX - (UINT32_MAX % static_cast<uint32_t>(word_list.size()))) {
                    break;
                }
            }

            if (i > 0) {
                password.push_back('-');
            }

            const std::string_view& word = word_list[value % static_cast<uint32_t>(word_list.size())];
            password.insert(password.end(), word.begin(), word.end());
        }

        if (!password.empty() && cap_first_letter) {
            password[0] = static_cast<char>(std::toupper(static_cast<unsigned char>(password[0])));
        }

        return *this;
    }

    PasswordGenerator& PasswordGenerator::pin(int length, Botan::secure_vector<uint8_t>& pin) {
        pin.clear();

        if (length <= 0) {
            return *this;
        }

        while (pin.size() < static_cast<size_t>(length)) {
            uint8_t value;

            if (RAND_bytes(&value, 1) != 1) {
                logger->error("RAND_bytes failed");
                pin.clear();
                return *this;
            }
            
            if (value >= 250) {
                continue;
            }

            pin.push_back('0' + (value % 10));
        }

        return *this;
    }
}