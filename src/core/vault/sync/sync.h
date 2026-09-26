#pragma once
#include <vector>
#include <shared>
#include <utility>
#include <nlohmann/json.hpp>
#include "../runtime/runtime.h"
#include "../network/network.h"
#include "thread/thread.h"
#include "clientwarden.h"

namespace clientwarden::vault {
    /**
     * @brief Represents the Local Sync State compared to the Remote Sync State.
     */
    enum class SyncState {
        Modified,
        CreatedOffline,
        PendingDelete,
        Clean
    };

    /**
     * @brief States weather a SyncRecord is for a Folder or Item.
     */
    enum class SyncItem {
        Item,
        Folder
    };

    /**
     * @brief States the Conflict type when compared to the Local and Remote versions.
     */
    enum class ConflictType {
        BothEdited,
        LocalDelete_RemoteUpdate,
        RemoteDelete_LocalUpdate
    };

    /**
     * @brief States the appropriate solution to the Conflict.
     */
    enum class ConflictSolution {
        Local,
        Remote,
        Merged,
        Unresolved
    };

    /**
     * @brief Represents the Items info and state which is used to diff local and remote changes.
     */
    struct SyncRecord {
        SyncItem item_type;
        ItemId uuid;
        int64_t revision;
        SyncState state;
        nlohmann::json raw;
    };

    /**
     * @brief Represents the Conflict between a local and remote record.
     */
    struct SyncConflict {
        ConflictType type;
        ConflictSolution solution;
        SyncRecord local;
        std::optional<SyncRecord> remote;
    };

    /**
     * @brief Sync Actions holds all the Sync Records on what actions to take to sync with the
     *  server.
     * @param push_create Pushes New Local Items to the server.
     * @param push_update Updates Newer Local Items to the server.
     * @param push_delete Removes items from the server that were deleted locally.
     * @param pull_create Pulls newly created items from the server to local.
     * @param pull_update Replaces newer modified items from the server to local.
     * @param pull_delete Removes items locally that were deleted from the server.
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

    /**
     * @brief Holds the results of the Remote Push to determine which records to retry later.
     */
    struct PushActions {
        std::vector<std::pair<ItemId, ItemId>> remap_id;
        std::vector<SyncRecord> success;
        std::vector<SyncRecord> failed;
    };

    class Sync {
    public:
        Sync(std::shared_ptr<Runtime> runtime, std::shared_ptr<Network> network, 
            std::shared_ptr<Settings> settings);
        virtual ~Sync() = default;

        /**
         * @brief Fetches Local and Remote Records and plans and resolves conflits. It then pushes
         *  the resulting changes to Server and to the Local JSON.
         */
        bool syncVault();
        /**
         * @brief Replaces the local Vault file with remote vault JSON.
         */
        virtual bool fullSync() = 0;

        /**
         * @brief Starts the SyncThread.
         * 
         * If the SyncMethod is WebSocket, it will use the NetworkThread, otherwise
         * it will manually sync every 5mins.
         */
        virtual bool startSyncThread() = 0;
        /**
         * @brief Stops the SyncThread.
         */
        virtual bool stopSyncThread() = 0;

        /**
         * @brief Gets the Vendor.
         */
        virtual Vendor getVendor() = 0;
    protected:
        /**
         * @brief Fetches local records and returns an array of SyncRecords.
         */
        virtual std::vector<SyncRecord> fetchLocalRecords() = 0;
        /**
         * @brief Fetches remote records and returns an array of SyncRecords.
         */
        virtual std::vector<SyncRecord> fetchRemoteRecords() = 0;
        
        /**
         * @brief Plans the appropriate Actions for local and remote records.
         */
        virtual SyncActions planActions(const std::vector<SyncRecord>& local, 
            const std::vector<SyncRecord>& remote) = 0;
        
        /**
         * @brief Pushes the SyncActions determined by planActions to remote.
         */
        virtual PushActions pushRemote(const SyncActions& actions) = 0;
        /**
         * @brief Updates the local db with the Push Actions returned by pushRemote.
         */
        virtual bool pushLocal(const PushActions& actions) = 0;
        
        /**
         * @brief Determines how to resolve conflicts between the local and remote versions.
         */
        virtual SyncActions resolveConflicts(const SyncActions& actions) = 0;

        std::shared_ptr<Runtime> m_runtime;
        std::shared_ptr<Network> m_network;
        std::shared_ptr<Settings> m_settings;
        Thread m_sync_thread;
    };
}