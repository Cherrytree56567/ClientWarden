#pragma once
#include <nlohmann/json.hpp>
#include <string>
#include <thread>
#include <chrono>
#include "Storage/Storage.h"

namespace ClientWarden {
    class Clipboard {
    public:
        Clipboard(std::shared_ptr<nlohmann::json> settingsData) : settingsData(settingsData) {}

        void Copy(std::string& str);
        void Paste(std::string& str);

        void SetDelay(int delay) {

        }

        int GetDelay() { 
            return 30;
        }
    private:
        std::shared_ptr<nlohmann::json> settingsData;
        Storage storage;
    };
}