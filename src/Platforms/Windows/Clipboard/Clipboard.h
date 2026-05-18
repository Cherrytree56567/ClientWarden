#pragma once
#include <winrt/Windows.ApplicationModel.DataTransfer.h>
#include <winrt/Windows.Foundation.h>
#include <openssl/crypto.h>
#include <Windows.h>
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