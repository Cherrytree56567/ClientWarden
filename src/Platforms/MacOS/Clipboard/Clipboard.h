#pragma once
#include <openssl/crypto.h>
#include <string>
#include <thread>
#include <chrono>
#include <nlohmann/json.hpp>
#include "Storage/Storage.h"

namespace ClientWarden {
    class Clipboard {
    public:
        Clipboard(std::shared_ptr<nlohmann::json> settingsData) : settingsData(settingsData) {}

        void Copy(std::string& str);
        void Paste(std::string& str);

        void SetDelay(int delay) { 
            secureDelayClear = delay; 
            (*settingsData)["clipboardClear"] = secureDelayClear;
            storage.write("settings.json", settingsData->dump(2));
        }
        int GetDelay() { return secureDelayClear; }
    private:
        int secureDelayClear = 30;
        std::shared_ptr<nlohmann::json> settingsData;
        Storage storage;
    };
}