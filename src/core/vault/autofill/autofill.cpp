#include "autofill.h"

namespace clientwarden::vault {
    AutoFill::AutoFill(std::shared_ptr<Runtime> runtime, std::shared_ptr<Orchestrator> orchestrator) 
        : m_runtime(runtime), m_orchestrator(orchestrator) {
        
    }
}