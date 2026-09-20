#pragma once
#include <thread>
#include <atomic>
#include <functional>

#include "Clientwarden.h"

namespace ClientWarden {
    class CWThread {
    public: 
        CWThread() = default;

        template <typename Func>
        explicit CWThread(Func&& func) : m_func(std::forward<Func>(func)) {
            
        }

        ~CWThread();

        /*
         * Templated func defs need to be in the class def file
        */
        template <typename Func>
        void setCallback(Func&& func) {
            m_func = std::forward<Func>(func);
        }

        void start();
        void stop();
    private:
        std::thread m_thread;
        std::atomic<bool> shouldThread { false };
        std::function<bool(const std::atomic<bool>&)> m_func;
    };
}