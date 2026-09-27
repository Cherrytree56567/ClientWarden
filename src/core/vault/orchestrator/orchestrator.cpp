#include "orchestrator.h"

namespace clientwarden::vault {
    Orchestrator::Orchestrator(std::shared_ptr<Crypto> crypto, std::shared_ptr<Network> network, 
        std::shared_ptr<Runtime> runtime) : m_crypto(crypto), m_network(network), m_runtime(runtime) {

    }

    std::shared_ptr<Runtime> getRuntime() {
        return m_runtime;
    }
}