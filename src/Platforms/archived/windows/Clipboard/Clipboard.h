#pragma once
#include <winrt/Windows.ApplicationModel.DataTransfer.h>
#include <winrt/Windows.Foundation.h>
#include <nlohmann/json.hpp>
#include <openssl/crypto.h>
#include <Windows.h>
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
            secureDelayClear = delay; 
            (*settingsData)["clipboardClear"] = secureDelayClear;
            storage.write("settings.json", settingsData->dump(2));
        }
        int GetDelay() { 
            if (!settingsData->contains("clipboardClear") || !(*settingsData)["clipboardClear"].is_number()) {
                (*settingsData)["clipboardClear"] = 30;
            }

            return (*settingsData)["clipboardClear"];
        }
    private:
        std::shared_ptr<nlohmann::json> settingsData;
        Storage storage;
    };
}