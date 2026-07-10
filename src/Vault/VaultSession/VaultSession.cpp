#include "VaultSession.h"

namespace ClientWarden {
    VaultSession::VaultSession {
        if (!logger) {
            spdlog::set_pattern("[%H:%M:%S] [%n] [%^---%L---%$] [thread %t] %v");

            auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
            auto file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(storage.path.string() + "/cw.log", true);

            logger = std::make_shared<spdlog::logger>("ClientWarden::VaultSession", spdlog::sinks_init_list{console_sink, file_sink});
            logger->set_level(spdlog::level::trace);
            logger->flush_on(spdlog::level::trace);
            spdlog::register_logger(logger);
        }
    }

    VaultSession::~VaultSession() {
        wssThread.stop();
        refreshThread.stop();
        connectivityThread.stop();
    }
}