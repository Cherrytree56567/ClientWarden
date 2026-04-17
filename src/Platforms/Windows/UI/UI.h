#pragma once
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include "Storage/Storage.h"

namespace ClientWarden::UI {
    class UI {
    public:
        UI();

        void Run();
    private:
        std::atomic<bool> run;
        Storage storage;
        std::shared_ptr<spdlog::logger> logger;
    };
}