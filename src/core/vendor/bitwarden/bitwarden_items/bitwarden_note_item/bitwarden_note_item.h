#pragma once
#include "items/generic_item_impl.h"
#include "../bitwarden_generic_item.h"

namespace clientwarden::vendor::bitwarden {
    class BitwardenNoteItem 
        : public GenericItemImpl<BitwardenGenericItem, BitwardenNoteItem> {
    public:
        BitwardenNoteItem(Vault& vault, ItemId id, bool item_creation);

        BitwardenNoteItem* duplicate(Botan::secure_vector<uint8_t>& id);
        
        BitwardenNoteItem* getType(ItemType& val);
    };
}