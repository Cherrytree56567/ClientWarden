#pragma once
#include <string>
#include <word_list.h>
#include "Storage/Storage.h"

namespace clientwarden {
    class PasswordGenerator {
    public:
        PasswordGenerator();
        ~PasswordGenerator();

        PasswordGenerator& random(int length, bool inc_num, bool inc_sym, bool caps, 
            Botan::secure_vector<uint8_t>& password);
        PasswordGenerator& memorable(int length, bool cap_first_letter, 
            Botan::secure_vector<uint8_t>& password);
        PasswordGenerator& pin(int length, Botan::secure_vector<uint8_t>& pin);
    private:
        std::shared_ptr<Storage> m_storage_;
        bool m_init_ = false;
    };
}