#pragma once
#include "vault/sync/sync.h"
#include "vault/orchestrator/orchestrator.h"

namespace clientwarden::vendor::bitwarden::vault {
    using namespace ::clientwarden::vault;
    using namespace ::clientwarden::platforms;
    
    class BitwardenSync : public Sync {
    public:
        explicit BitwardenSync(std::shared_ptr<Runtime> runtime, std::shared_ptr<Network> network, 
            std::shared_ptr<Orchestrator> orchestrator, std::shared_ptr<Settings> settings, 
            std::shared_ptr<Storage> storage);
        ~BitwardenSync() override = default;
        
        std::expected<bool, SyncError> fullSync() override;

        std::expected<bool, SyncError> startSyncThread() override;
        std::expected<bool, SyncError> stopSyncThread() override;

        SyncError syncItem(ItemId id, SyncItem item_type, SyncState item_state) override;

        Vendor getVendor() override;
    protected:
        std::expected<std::vector<SyncRecord>, SyncError> fetchLocalRecords() override;
        std::expected<std::vector<SyncRecord>, SyncError> fetchRemoteRecords() override;
        std::expected<SyncActions, SyncError> planActions(const std::vector<SyncRecord>& local, 
            const std::vector<SyncRecord>& remote) override;
        std::expected<PushActions, SyncError> pushRemote(const SyncActions& actions) override;
        std::expected<bool, SyncError> pushLocal(const PushActions& actions) override;
        std::expected<SyncActions, SyncError> resolveConflicts(const SyncActions& actions) override;
    private:
        /**
         * @brief Merges 2 nlohmann::json objects/values.
         * @param value_1 Provides the first value to compare.
         * @param value_2 Provides the second value to compare.
         * @param on_conflict States weather (true) a wins or (false) b wins.
         */
        nlohmann::json mergeValues_(nlohmann::json value_1, nlohmann::json value_2, bool on_conflict);
        /**
         * @brief Merges 2 nlohmann::json objects/values with a base
         * @param base Provides the base to compare off
         * @param value_1 Provides the first value to compare.
         * @param value_2 Provides the second value to compare.
         * @param on_conflict States weather (true) a wins or (false) b wins.
         */
        nlohmann::json mergeValues_(nlohmann::json base, nlohmann::json value_1, nlohmann::json value_2, 
            bool on_conflict);
        
        bool syncCallback(const std::atomic<bool>&);
    };
}