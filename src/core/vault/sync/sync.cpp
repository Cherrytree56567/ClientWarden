#include "sync.h"

namespace clientwarden::vault {
    Sync::Sync(std::shared_ptr<Runtime> runtime, std::shared_ptr<Network> network, 
        std::shared_ptr<Orchestrator> orchestrator, std::shared_ptr<Settings> settings, 
        std::shared_ptr<Storage> storage) :
        m_runtime(runtime), m_network(network), m_settings(settings), m_storage(storage),
        m_orchestrator(orchestrator) {
        
    }

    std::expected<bool, SyncError> Sync::syncVault() {
        std::expected<std::vector<SyncRecord>, SyncError> local_records = fetchLocalRecords();

        if (!local_records.has_value()) {
            return std::unexpected(SyncError::StorageFailure);
        }

        std::expected<std::vector<SyncRecord>, SyncError> remote_records = fetchRemoteRecords();

        if (!remote_records.has_value()) {
            return std::unexpected(SyncError::RuntimeError);
        }

        std::expected<SyncActions, SyncError> actions = planActions(local_records.value(), remote_records.value());

        if (!actions.has_value()) {
            return std::unexpected(SyncError::SyncError);
        }

        if (!actions.value().conflicts.empty()) {
            actions = resolveConflicts(actions.value());
        }

        std::expected<PushActions, SyncError> push_actions = pushRemote(actions.value());

        if (!push_actions.has_value()) {
            return std::unexpected(SyncError::SyncError);
        }

        std::expected<bool, SyncError> result = pushLocal(push_actions.value());

        return result;
    }
}