#include "folder.h"

namespace clientwarden {
    Folder::Folder(Vault& vault, ItemId id, bool item_creation) : m_id(id),
        m_is_created(item_creation), m_vault(vault) {
        m_init = true;
    }
}