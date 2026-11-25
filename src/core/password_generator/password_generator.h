#pragma once
#include <string>
#include <wordlist.h>
#include <botan/auto_rng.h>
#include <botan/system_rng.h>
#include "storage/storage.h"
#include "crypto/crypto.h"
#include "clientwarden.h"

namespace clientwarden {
    using namespace ::clientwarden::vault;
    using namespace ::clientwarden::platforms;

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
        static thread_local Botan::AutoSeeded_RNG m_rng_;
    };
}