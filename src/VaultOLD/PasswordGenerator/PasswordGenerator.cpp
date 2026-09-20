#include "PasswordGenerator.h"

namespace ClientWarden {
    PasswordGenerator::PasswordGenerator() : storage("") {
        std::string file = storage.read("clientgen.txt"); // TODO: Add clientgen.txt to bundle

        std::stringstream ss(file);
        std::string line;

        while (std::getline(ss, line, '\n')) {
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }
            wordList.push_back(line);
        }

        init = true;
    }

    PasswordGenerator::~PasswordGenerator() {
        wordList.clear();
    }

    PasswordGenerator& PasswordGenerator::Random(int Characters, bool incNumbers, bool incSymbols, bool caps, std::string& password) {
        if (!init) return *this;
        std::vector<std::string> chars = alphabets;
        if (caps) {
            chars.insert(chars.end(), alphabetsCaps.begin(), alphabetsCaps.end());
        }
        if (incNumbers) {
            chars.insert(chars.end(), numbers.begin(), numbers.end());
        }
        if (incSymbols) {
            chars.insert(chars.end(), symbols.begin(), symbols.end());
        }

        password.resize(Characters);

        Botan::secure_vector<uint8_t> randomBuf(Characters);
        if (RAND_bytes(randomBuf.data(), Characters) != 1) {
            logger->error("RAND_bytes failed");
            return *this;
        }

        for (int i = 0; i < Characters; ++i) {
            password[i] = chars[randomBuf[i] % chars.size()][0];
        }
        
        Botan::secure_scrub_memory(randomBuf.data(), randomBuf.size());
        return *this;
    }

    PasswordGenerator& PasswordGenerator::Memorable(int Characters, bool capFirstLetter, std::string& password) {
        if (!init) return *this;
        password.clear();
        for (int i = 0; i < Characters; i++) {
            uint32_t randVal;
            if (RAND_bytes(reinterpret_cast<uint8_t*>(&randVal), sizeof(randVal)) != 1) {
                logger->error("RAND_bytes failed");
                return *this;
            }
            password += wordList[randVal % wordList.size()] + "-";
        }
        if (!password.empty() && password.back() == '-') {
            password.pop_back();
        }
        if (!password.empty() && capFirstLetter) {
            password[0] = std::toupper(password[0]);
        }

        return *this;
    }

    PasswordGenerator& PasswordGenerator::Pin(int Characters, std::string& pin) {
        if (!init) return *this;
        pin.resize(Characters);

        Botan::secure_vector<uint8_t> randomBuf(Characters);
        if (RAND_bytes(randomBuf.data(), Characters) != 1) {
            logger->error("RAND_bytes failed");
            return *this;
        }

        for (int i = 0; i < Characters; ++i) {
            pin[i] = '0' + (randomBuf[i] % 10);
        }

        Botan::secure_scrub_memory(randomBuf.data(), randomBuf.size());
        return *this;
    }
}