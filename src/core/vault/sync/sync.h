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

    struct SyncRecord {
        SyncItem item_type;
        boost::uuids::uuid uuid;
        int64_t revision;
        SyncState state;
        nlohmann::json raw;
    };

    struct SyncActions {
        std::vector<SyncRecord> push_create;
        std::vector<SyncRecord> push_update;
        std::vector<SyncRecord> push_delete;
        std::vector<SyncRecord> pull_create;
        std::vector<SyncRecord> pull_update;
        std::vector<SyncRecord> pull_delete;
    };

    class Sync {
    public:
        
    };
}