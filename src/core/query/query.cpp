#include "query.h"

namespace clientwarden {
    Query::Query(Vault& vault) : m_vault(vault) {
        m_init = true;
    }
}