#pragma once
#include <thread>
#include <atomic>
#include <functional>
#include "clientwarden.h"

namespace clientwarden {
    class Thread {
    public: 
        Thread() = default;

        template <typename Func>
        explicit Thread(Func&& func) : m_func_(std::forward<Func>(func)) {
            
        }

        ~Thread();

        template <typename Func>
        void setCallback(Func&& func) {
            m_func_ = std::forward<Func>(func);
        }

        void start();
        void stop();
    private:
        std::thread m_thread_;
        std::atomic<bool> m_should_thread_ { false };
        std::function<bool(const std::atomic<bool>&)> m_func_;
    };
}