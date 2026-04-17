#pragma once
#include <string>
#include <vector>
#include <regex>
#include <openssl/rand.h>
#include <nlohmann/json.hpp>
#include "../CommonVault.h"
#include "../VaultUtils/VaultUtils.h"
#include "../Vault.h"

namespace ClientWarden::Vault {
    class PasswordGenerator {
    public:
        PasswordGenerator(Vault& vault);
        ~PasswordGenerator();

        PasswordGenerator& Random(int Characters, bool incNumbers, bool incSymbols, bool caps, std::string& password);
        PasswordGenerator& Memorable(int Characters, bool capFirsrLetter, std::string& password);
        PasswordGenerator& Pin(int Characters, std::string& pin);
    private:
        Vault& localVault;
        Storage storage;
        std::shared_ptr<spdlog::logger> logger;

        bool init = false;

        std::vector<std::string> wordList;

        std::vector<std::string> alphabets = {"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z"};
        std::vector<std::string> alphabetsCaps = {"A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z"};
        std::vector<std::string> numbers = {"1", "2", "3", "4", "5", "6", "7", "8", "9", "0"};
        std::vector<std::string> symbols = {"`", "~", "!", "@", "#", "$", "%", "^", "&", "*", "(", ")", "-", "_", "+", "=", "{", "[", "}", "]", "\\", "|", ";", ":", "'", "\"", "<", ",", ">", ".", "?", "/"};
    };
}