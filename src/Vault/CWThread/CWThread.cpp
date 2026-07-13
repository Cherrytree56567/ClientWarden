#include "CWThread.h"

namespace ClientWarden {
    CWThread::~CWThread() {
        stop();
    }

    void CWThread::start() {
        if (m_thread.joinable()) {
            return;
        }

        if (!m_func) {
            logger->error("No callback set");
            return;
        }

        shouldThread = true;
        m_thread = std::thread([this]() {
            m_func(shouldThread);
        });
    }

    void CWThread::stop() {
        shouldThread = false;
        if (m_thread.joinable()) {
            m_thread.join();
        }
    }
}