#pragma once

namespace clientwarden::vault {
    enum class SyncState {
        Modified,
        CreatedOffline,
        PendingDelete,
        Clean
    };

    enum class SyncItem {
        Item,
        Folder
    };

    enum class ConflictType {
        BothEdited,
        LocalDelete_RemoteUpdate,
        RemoteDelete_LocalUpdate
    };

    enum class ConflictSolution {
        Local,
        Remote,
        Unresolved
    };

    struct SyncRecord {
        SyncItem item_type;
        boost::uuids::uuid uuid;
        int64_t revision;
        SyncState state;
        nlohmann::json raw;
    };

    struct SyncConflict {
        ConflictType type;
        ConflictSolution solution;
        SyncRecord local;
        std::optional<SyncRecord> remote;
    };

    /**
     * @brief Sync Actions holds all the Sync Records on what actions to take to sync with the
     *  server
     * @param push_create Pushes New Local Items to the server
     * @param push_update Updates Newer Local Items to the server
     * @param push_delete Removes items from the server that were deleted locally
     * @param pull_create Pulls newly created items from the server to local
     * @param pull_update Replaces newer modified items from the server to local
     * @param pull_delete Removes items locally that were deleted from the server
     */
    struct SyncActions {
        std::vector<SyncRecord> push_create;
        std::vector<SyncRecord> push_update;
        std::vector<SyncRecord> push_delete;
        std::vector<SyncRecord> pull_create;
        std::vector<SyncRecord> pull_update;
        std::vector<SyncRecord> pull_delete;
        std::vector<SyncConflict> conflicts;
    };

    struct PushActions {
        std::vector<std::pair<boost::uuids::uuid, boost::uuids::uuid>> remap_id;
        std::vector<SyncRecord> success;
        std::vector<SyncRecord> failed;
    };

    class Sync {
    public:
        Sync(std::shared_ptr<Runtime> runtime, std::shared_ptr<Network> network);
        virtual ~Sync() = default;

        bool syncVault(bool fullSync = false);

        virtual Vendor getVendor() = 0;
    protected:
        virtual std::vector<SyncRecord> fetchLocalRecords() = 0;
        virtual std::vector<SyncRecord> fetchRemoteRecords() = 0;
        
        virtual SyncActions planActions(const std::vector<SyncRecord>& local, 
            const std::vector<SyncRecord>& remote) = 0;
        
        virtual PushActions pushRemote(const SyncActions& actions) = 0;
        virtual bool pushLocal(const PushActions& actions) = 0;

        std::shared_ptr<Runtime> m_runtime;
        std::shared_ptr<Network> m_network;
    };
}