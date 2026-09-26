#include "versioning.h"

namespace clientwarden::vault {
    Versioning::Versioning(std::shared_ptr<Network> network, std::shared_ptr<Session> session) : 
        m_network(network), m_session(session) {
        
    }
}