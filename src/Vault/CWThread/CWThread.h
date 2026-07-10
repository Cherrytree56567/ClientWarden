#pragma once
#include <thread>
#include <atomic>
#include <functional>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/basic_file_sink.h>

namespace ClientWarden {
    class CWThread {
    public: 
        CWThread() = default;

        template <typename Func, typename... Args>
        explicit CWThread(Func&& func, Args&&... args) : m_func(std::bind(std::forward<Func>(func), std::forward<Args>(args)...)) {
            if (!logger) {
                spdlog::set_pattern("[%H:%M:%S] [%n] [%^---%L---%$] [thread %t] %v");

                auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
                auto file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(storage.path.string() + "/cw.log", true);

                logger = std::make_shared<spdlog::logger>("ClientWarden::Thread", spdlog::sinks_init_list{console_sink, file_sink});
                logger->set_level(spdlog::level::trace);
                logger->flush_on(spdlog::level::trace);
                spdlog::register_logger(logger);
            }
        }

        ~CWThread();

        /*
         * Templated func defs need to be in the class def file
        */
        template <typename Func, typename... Args>
        void setCallback(Func&& func, Args&&... args) {
            m_func = std::bind(std::forward<Func>(func), std::forward<Args>(args)...);
        }

        void start();
        void stop();
    private:
        std::thread m_thread;
        std::atomic<bool> shouldThread { false };
        std::function<bool(const std::atomic<bool>&)> m_func;
        inline static std::shared_ptr<spdlog::logger> logger;
    };
}