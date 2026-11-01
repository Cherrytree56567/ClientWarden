#include "runtime.h"

namespace clientwarden::vault {
    Runtime::Runtime(std::shared_ptr<Storage> storage) : m_storage(storage) {
        
    }
}