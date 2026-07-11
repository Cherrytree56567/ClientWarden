#pragma once
#include <string>
#include <vector>
#include <nlohmann/json.hpp>
#include "../GenericItem/GenericItem.h"

namespace ClientWarden {
    class NoteItem : public GenericItemImpl<NoteItem> {
    public:
        NoteItem(Vault& vault, std::string uuid); // Existing Item
        NoteItem(Vault& vault); // New Item

        NoteItem* Duplicate(std::string& id);

        NoteItem* GetType(CipherType& val) override;
    private:
        inline static std::shared_ptr<spdlog::logger> l_logger = nullptr;
    };
}