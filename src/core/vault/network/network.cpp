#include "network.h"

namespace clientwarden::vault {
    Network::Network(std::shared_ptr<Settings> settings) : m_settings(settings) {
        
    }

    void Network::setEventHandler(std::function<void(NetworkEvent)> on_event) {
        m_on_event = on_event;
    }
}