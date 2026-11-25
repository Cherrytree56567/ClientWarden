#include "vault.h"

namespace clientwarden::vault {
    Vault::Vault(ItemId uuid) : m_uuid_(uuid), 
        m_storage_(std::make_shared<Storage>(uuid)), 
        m_settings(std::make_shared<Settings>(m_storage_)), 
        m_network(std::make_shared<Network>(m_settings)), 
        m_runtime(std::make_shared<Runtime>(m_storage_)), 
        m_versioning(std::make_shared<Versioning>(m_runtime)), 
        m_orchestrator(std::make_shared<Orchestrator>(m_crypto, m_network, m_runtime, m_storage_)), 
        m_autofill(std::make_shared<AutoFill>(m_runtime, m_orchestrator, m_crypto)), 
        m_sync(std::make_shared<Sync>(m_runtime, m_network, m_settings, m_storage_)) {
        
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