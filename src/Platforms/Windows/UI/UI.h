#pragma once
#include <spdlog/spdlog.h>
#include <openssl/crypto.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include "Storage/Storage.h"

namespace ClientWarden::UI {
    class UI {
    public:
        UI();

        void Run();
        void Start();
        void Stop();

        void login(std::string& email, std::string& password);
        void unlock(std::string& password);
    private:
        std::atomic<bool> run;
        std::thread uiThread;

        std::atomic<bool> isLogin;
        bool loginDone;
        std::mutex loginMutex;
        std::condition_variable loginCV;
        std::string* email = nullptr;
        std::string* password = nullptr;

        std::atomic<bool> isUnlock;
        bool unlockDone;
        std::mutex unlockMutex;
        std::condition_variable unlockCV;
        std::string* UnlockPassword = nullptr;

        Storage storage;
        std::shared_ptr<spdlog::logger> logger;
    };
}