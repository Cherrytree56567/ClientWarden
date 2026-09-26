#include "thread.h"

namespace clientwarden {
    Thread::~Thread() {
        stop();
    }

    void Thread::start() {
        if (m_thread_.joinable()) {
            return;
        }

        if (!m_func_) {
            g_logger->error("No callback set");
            return;
        }

        m_should_thread_ = true;
        m_thread_ = std::thread([this]() {
            m_func_(m_should_thread_);
        });
    }

    void Thread::stop() {
        if (m_should_thread_ == false) {
            return;
        }

        m_should_thread_ = false;
        
        if (m_thread_.joinable()) {
            m_thread_.join();
        }
    }
}