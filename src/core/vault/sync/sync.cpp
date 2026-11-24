#include "sync.h"

namespace clientwarden::vault {
    Sync::Sync(std::shared_ptr<Runtime> runtime, std::shared_ptr<Network> network, 
        std::shared_ptr<Orchestrator> orchestrator, std::shared_ptr<Settings> settings, 
        std::shared_ptr<Storage> storage) :
        m_runtime(runtime), m_network(network), m_settings(settings), m_storage(storage),
        m_orchestrator(orchestrator) {
        
    }

    bool Sync::syncVault() {
        std::vector<SyncRecord> local_records = fetchLocalRecords();
        std::vector<SyncRecord> remote_records = fetchRemoteRecords();

        SyncActions actions = planActions(local_records, remote_records);

        if (!actions.conflicts.empty()) {
            actions = resolveConflicts(actions);
        }

        PushActions push_actions = pushRemote(actions);

        bool result = pushLocal(push_actions);

        return result;
    }
}