#pragma once
#include <openssl/crypto.h>
#include <string>
#include <thread>
#include <chrono>

namespace ClientWarden {
    class Clipboard {
    public:
        Clipboard() {}

        void Copy(std::string& str);
        void Paste(std::string& str);

        void SetDelay(int delay) { secureDelayClear = delay; }
    private:
        int secureDelayClear = 30;
    };
}