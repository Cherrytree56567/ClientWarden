#pragma once
#include "items/generic_item_impl.h"
#include "../bitwarden_generic_item.h"

namespace clientwarden::vendor::bitwarden {
    class BitwardenNoteItem 
        : public GenericItemImpl<BitwardenGenericItem, BitwardenNoteItem> {
    public:
        BitwardenNoteItem(Vault& vault, ItemId id, bool item_creation);

        BitwardenNoteItem* duplicate(ItemId& id);
        
        BitwardenNoteItem* getType(ItemType& val);
    };
}