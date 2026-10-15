#pragma once
#include "vault/sync/sync.h"

namespace clientwarden::vendor::bitwarden::vault {
    class BitwardenSync : public Sync {
    public:
        explicit BitwardenSync(std::shared_ptr<Runtime> runtime, std::shared_ptr<Network> network, 
            std::shared_ptr<Settings> settings);
        ~BitwardenSync() override = default;
        
        std::expected<bool, SyncError> fullSync() override;

        std::expected<bool, SyncError> startSyncThread() override;
        std::expected<bool, SyncError> stopSyncThread() override;

        Vendor getVendor() override;
    protected:
        std::expected<std::vector<SyncRecord>, SyncError> fetchLocalRecords() override;
        std::expected<std::vector<SyncRecord>, SyncError> fetchRemoteRecords() override;
        std::expected<SyncActions, SyncError> planActions(const std::vector<SyncRecord>& local, 
            const std::vector<SyncRecord>& remote) override;
        std::expected<PushActions, SyncError> pushRemote(const SyncActions& actions) override;
        std::expected<bool, SyncError> pushLocal(const PushActions& actions) override;
        std::expected<SyncActions, SyncError> resolveConflicts(const SyncActions& actions) override;
    };
}