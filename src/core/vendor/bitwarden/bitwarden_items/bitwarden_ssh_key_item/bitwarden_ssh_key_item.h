#pragma once
#include "items/generic_item_impl.h"
#include "../bitwarden_generic_item.h"

namespace clientwarden::vendor::bitwarden {
    class BitwardenSSHKeyItem 
        : public GenericItemImpl<BitwardenGenericItem, BitwardenSSHKeyItem> {
    public:
        BitwardenSSHKeyItem(Vault& vault, ItemId id, bool item_creation);

        BitwardenSSHKeyItem* setFingerprint(const Botan::secure_vector<uint8_t>& fingerprint);
        BitwardenSSHKeyItem* setPrivateKey(const Botan::secure_vector<uint8_t>& private_key);
        BitwardenSSHKeyItem* setPublicKey(const Botan::secure_vector<uint8_t>& public_key);

        BitwardenSSHKeyItem* duplicate(Botan::secure_vector<uint8_t>& id);

        BitwardenSSHKeyItem* getFingerprint(Botan::secure_vector<uint8_t>& fingerprint);
        BitwardenSSHKeyItem* getPrivateKey(Botan::secure_vector<uint8_t>& private_key);
        BitwardenSSHKeyItem* getPublicKey(Botan::secure_vector<uint8_t>& public_key);
        BitwardenSSHKeyItem* getType(ItemType& val);
    };
}