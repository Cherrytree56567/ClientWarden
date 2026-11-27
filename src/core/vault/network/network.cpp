#include "network.h"

namespace clientwarden::vault {
    Network::Network(std::shared_ptr<Settings> settings) : m_settings(settings) {
        
    }

    void Network::setEventHandler(
        std::function<void(NetworkEvent, std::string, nlohmann::json)> on_event) {
        m_on_event = on_event;
    }

    void Network::setSession(const AuthSession& session) {
        m_session = session;
    }

    void Network::eraseSession() {
        m_session.clear();
    }
}