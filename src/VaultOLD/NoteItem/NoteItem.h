#pragma once
#include <string>
#include <vector>
#include <nlohmann/json.hpp>
#include "../GenericItem/GenericItemImpl.h"

#include "Clientwarden.h"

namespace ClientWarden {
    class NoteItem : public GenericItemImpl<NoteItem> {
    public:
        NoteItem(Vault& vault, std::string uuid); // Existing Item
        NoteItem(Vault& vault); // New Item

        NoteItem* Duplicate(std::string& id);

        NoteItem* GetType(CipherType& val);
    };
}