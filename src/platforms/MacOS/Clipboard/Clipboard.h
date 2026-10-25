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
            (*settingsData)["clipboardClear"] = delay;
            storage.write("settings.json", settingsData->dump(2));
        }

        int GetDelay() { 
            if (!settingsData->contains("clipboardClear") || !(*settingsData)["clipboardClear"].is_number()) {
                (*settingsData)["clipboardClear"] = 30;
                storage.write("settings.json", settingsData->dump(2));
            }

            return (*settingsData)["clipboardClear"];
        }
    private:
        std::shared_ptr<nlohmann::json> settingsData;
        Storage storage;
    };
}