#include "versioning.h"

namespace clientwarden::vault {
    Versioning::Versioning(std::shared_ptr<Network> network, std::shared_ptr<Runtime> runtime) : 
        m_network(network), m_runtime(runtime) {
        
    }
}