#include <catch2/reporters/catch_reporter_registrars.hpp>
#include <catch2/reporters/catch_reporter_event_listener.hpp>
#include <spdlog/sinks/stdout_color_sinks.h>
#include "Clientwarden.h"

struct TestSetup : Catch::EventListenerBase {
    using Catch::EventListenerBase::EventListenerBase;

    void testRunStarting(Catch::TestRunInfo const&) override {
        if (!ClientWarden::logger) {
            spdlog::set_pattern("[%H:%M:%S] [%n] [%^---%L---%$] [thread %t] %v");

            auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();

            ClientWarden::logger = std::make_shared<spdlog::logger>("ClientWarden::Vault", spdlog::sinks_init_list{console_sink});
            ClientWarden::logger->set_level(spdlog::level::trace);
            ClientWarden::logger->flush_on(spdlog::level::trace);
            spdlog::register_logger(ClientWarden::logger);
        }
    }
};

CATCH_REGISTER_LISTENER(TestSetup)

