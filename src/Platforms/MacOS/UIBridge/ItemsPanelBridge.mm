#import "ItemsPanelBridge.h"
#import <Cocoa/Cocoa.h>
#import "clientwarden-Swift.h"
#include "CipherQuery/CipherQuery.h"
#include "GenericItem/GenericItem.h"
#include "LoginItem/LoginItem.h"
#include "CardItem/CardItem.h"
#include "IdentityItem/IdentityItem.h"
#include "NoteItem/NoteItem.h"
#include "SSHKeyItem/SSHKeyItem.h"
#include "Folder/Folder.h"

/*
 * IDK what Im even doing here
 * Objective-C++ is soo weird, 
 * and I can't get any syntax 
 * highlighting for cpp stuff 
 * in here.
 *
 * tbh Ill do this later.
 */
@implementation ItemsPanelBridge

+ (void)setupCallbacks {
    [self cb_query];
    [self cb_new];
}

+ (NSArray<ItemElement*>*)getItems:(std::vector<std::pair<ClientWarden::CipherType, std::string>>)ciphers {
    ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

    NSMutableArray<ItemElement*>* items = [NSMutableArray array];

    for (auto& cipher : ciphers) {
        NSUUID* uuid = [[NSUUID alloc] initWithUUIDString:[NSString stringWithUTF8String: cipher.second.c_str()]];

        ClientWarden::GenericItem item(v_inst, cipher.second);

        std::string c_name;

        item.GetName(c_name)->Close();

        NSString* name = [NSString stringWithUTF8String: c_name.c_str()];

        ClientwardenImage* img = nil;

        if (cipher.first == ClientWarden::CipherType::Login) {
            ClientWarden::LoginItem cip(v_inst, cipher.second);

            std::vector<std::string> loginUrl;

            cip.GetWebsites(loginUrl)->Close();

            if (loginUrl.size() != 0) {
                std::string c_path = v_inst.downloadIcon(loginUrl[0]);
                NSString* path = [NSString stringWithUTF8String: c_path.c_str()];

                img = [[ClientwardenImage alloc] initWithType:ImageTypeAppSupport path:path];
            } else {
                img = [[ClientwardenImage alloc] initWithType:ImageTypeSystemImage path:@"globe"];
            }

            for (auto& uri : loginUrl) {
                OPENSSL_cleanse(uri.data(), uri.size());
                uri.clear();
            }
        } else if (cipher.first == ClientWarden::CipherType::Card) {
            img = [[ClientwardenImage alloc] initWithType:ImageTypeSystemImage path:@"creditcard"];
        } else if (cipher.first == ClientWarden::CipherType::Identity) {
            img = [[ClientwardenImage alloc] initWithType:ImageTypeSystemImage path:@"person.text.rectangle"];
        } else if (cipher.first == ClientWarden::CipherType::Note) {
            img = [[ClientwardenImage alloc] initWithType:ImageTypeSystemImage path:@"pad.header"];
        } else if (cipher.first == ClientWarden::CipherType::SSHKey) {
            img = [[ClientwardenImage alloc] initWithType:ImageTypeSystemImage path:@"key.viewfinder"];
        }

        ItemType i_type = (ItemType)((int)cipher.first - 1);

        ItemElement* element = [[ItemElement alloc] initWithName:name uuid:uuid type:i_type image:img];

        [items addObject:element];
    }

    return items;
}

+ (void)cb_query {
    ItemsPanel.instance.cb_query = ^NSArray* _Nonnull(NSString* name) {
        ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();
        ClientWarden::CipherQuery query(v_inst);

        std::string c_name = name.UTF8String;

        std::vector<std::pair<ClientWarden::CipherType, std::string>> ciphers = query.FilterByUnbinned()
                                                                                     .FilterNameByRegex(c_name)
                                                                                     .GetCiphers();

        return [ItemsPanelBridge getItems:ciphers];
    };
}

+ (void)cb_new {
    ItemsPanel.instance.cb_new = ^ItemElement* _Nullable(ItemType i_type) {
        ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

        ClientWarden::GenericItem* item = nullptr;

        ClientwardenImage* img = nil;
        NSString* name = @"New Item";
        
        if (i_type == ItemTypeLogin) {
            item = new ClientWarden::LoginItem(v_inst);
            img = [[ClientwardenImage alloc] initWithType:ImageTypeSystemImage path:@"globe"];
        } else if (i_type == ItemTypeCard) {
            item = new ClientWarden::CardItem(v_inst);
            img = [[ClientwardenImage alloc] initWithType:ImageTypeSystemImage path:@"creditcard"];
        } else if (i_type == ItemTypeIdentity) {
            item = new ClientWarden::IdentityItem(v_inst);
            img = [[ClientwardenImage alloc] initWithType:ImageTypeSystemImage path:@"person.text.rectangle"];
        } else if (i_type == ItemTypeNote) {
            item = new ClientWarden::NoteItem(v_inst);
            img = [[ClientwardenImage alloc] initWithType:ImageTypeSystemImage path:@"pad.header"];
        } else if (i_type == ItemTypeSSHKey) {
            item = new ClientWarden::SSHKeyItem(v_inst);
            img = [[ClientwardenImage alloc] initWithType:ImageTypeSystemImage path:@"key.viewfinder"];
        }

        std::string c_name = "New Item";
        std::string c_uuid = "";

        item->SetName(c_name)
            ->GetId(c_uuid)
            ->Commit();
        
        NSString* s_uuid = [NSString stringWithUTF8String: c_uuid.c_str()];
        NSUUID* uuid = [[NSUUID alloc] initWithUUIDString: s_uuid];

        return [[ItemElement alloc] initWithName:name uuid:uuid type:i_type image:img];
    };
}

@end