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

        /**
         * @brief Sets the Thread Function.
         */
        template <typename Func>
        void setCallback(Func&& func) {
            m_func_ = std::forward<Func>(func);
        }

        /**
         * @brief Starts the Thread.
         */
        void start();
        /**
         * @brief Stops the Thread.
         */
        void stop();
    private:
        std::thread m_thread_;
        std::atomic<bool> m_should_thread_ { false };
        std::function<bool(const std::atomic<bool>&)> m_func_;
    };
}