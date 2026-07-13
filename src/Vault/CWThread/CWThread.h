#pragma once
#include <thread>
#include <atomic>
#include <functional>

#include "Clientwarden.h"

namespace ClientWarden {
    class CWThread {
    public: 
        CWThread() = default;

        template <typename Func, typename... Args>
        explicit CWThread(Func&& func, Args&&... args) : m_func(std::bind(std::forward<Func>(func), std::forward<Args>(args)...)) {
            
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
    };
}