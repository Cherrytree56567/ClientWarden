#import "NavPanelBridge.h"
#import "clientwarden-Swift.h"
#include "CipherQuery.h"

/*
 * IDK what Im even doing here
 * Objective-C++ is soo weird, 
 * and I can't get any syntax 
 * highlighting for cpp stuff 
 * in here.
 *
 * tbh Ill do this later.
 */
@implementation NavPanelBridge

+ (void)setupCallbacks {
    [self cb_AllItems];
    [self cb_Favorites];
    [self cb_Trash];
    [self cb_Login];
    [self cb_Card];
    [self cb_Identity];
    [self cb_Note];
    [self cb_SSHKey];
    [self cb_Folder];
    [self cb_CreateFolder];
    [self cb_DeleteFolder];
}

+ (void)cb_AllItems {
    NavigationPanel.instance.cb_allItems = ^NSArray * _Nonnull {
        Vault& v_inst = Vault::instance();
        CipherQuery query(v_inst);

        std::vector<std::pair<CipherType, std::string>> ciphers = query.FilterByUnbinned().GetCiphers();
        std::vector<ClientWarden::ItemData> items;

        for (auto& cipher : ciphers) {
            NSUUID* uuid = [[NSUUID alloc] initWithUUIDString:[NSString stringWithUTF8String: cipher.second.c_str()]];

            GenericItem item(v_inst, cipher.second);

            std::string c_name;

        }

        return [VaultBridge convertItems:items];
    };
}