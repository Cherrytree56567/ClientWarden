#include "orchestrator.h"

namespace clientwarden::vault {
    Orchestrator::Orchestrator(std::shared_ptr<Crypto> crypto, std::shared_ptr<Network> network, 
        std::shared_ptr<Runtime> runtime, std::shared_ptr<Storage> storage) : m_crypto(crypto), 
        m_network(network), m_runtime(runtime), m_storage(storage) {

    }

    std::shared_ptr<Runtime> getRuntime() {
        return m_runtime;
    }

    std::shared_ptr<Crypto> getCrypto() {
        return m_crypto;
    }
}