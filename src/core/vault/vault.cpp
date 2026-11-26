#include "vault.h"

namespace clientwarden {
    Vault::Vault(ItemId uuid) : m_uuid_(uuid), 
        m_storage_(std::make_shared<Storage>(uuid)), 
        m_settings(std::make_shared<Settings>(uuid)) {
        
    }

    AuthState Vault::getState() {
        return m_state;
    }

    std::shared_ptr<vault::Orchestrator> Vault::getOrchestrator() {
        return m_orchestrator;
    }

    std::shared_ptr<vault::Versioning> Vault::getVersioning() {
        return m_versioning;
    }

    std::shared_ptr<vault::Settings> Vault::getSettings() {
        return m_settings;
    }

    std::shared_ptr<vault::AutoFill> Vault::getAutoFill() {
        return m_autofill;
    }

    std::shared_ptr<Storage> Vault::getStorage() {
        return m_storage_;
    }
}