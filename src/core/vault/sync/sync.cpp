#include "sync.h"

namespace clientwarden::vault {
    Sync::Sync(std::shared_ptr<Runtime> runtime, std::shared_ptr<Network> network) :
        m_runtime(runtime), m_network(network) {
        
    }

    bool Sync::syncVault(bool fullSync = false) {
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