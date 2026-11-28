#include <catch2/reporters/catch_reporter_registrars.hpp>
#include <catch2/reporters/catch_reporter_event_listener.hpp>
#include <spdlog/sinks/stdout_color_sinks.h>
#include "clientwarden.h"

struct TestSetup : Catch::EventListenerBase {
    using Catch::EventListenerBase::EventListenerBase;

    void testRunStarting(Catch::TestRunInfo const&) override {
        if (!ClientWarden::logger) {
            spdlog::set_pattern("[%H:%M:%S] [%n] [%^---%L---%$] [thread %t] %v");

            std::shared_ptr<spdlog::sinks::stdout_color_sink_mt> console_sink = 
                std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
            std::shared_ptr<spdlog::sinks::basic_file_sink_mt> file_sink = 
                std::make_shared<spdlog::sinks::basic_file_sink_mt>(m_storage_.getPath().string() + "/cw.log", true);

            clientwarden::g_logger = std::make_shared<spdlog::logger>("ClientWarden", spdlog::sinks_init_list{console_sink, file_sink});
            clientwarden::g_logger->set_level(spdlog::level::trace);
            clientwarden::g_logger->flush_on(spdlog::level::trace);
            spdlog::register_logger(clientwarden::g_logger);
        }
    }
};

CATCH_REGISTER_LISTENER(TestSetup)

