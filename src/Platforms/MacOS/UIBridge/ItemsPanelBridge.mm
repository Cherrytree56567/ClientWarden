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
#include "Vault.h"

@implementation ItemsPanelBridge

/*
 * Setup Callbacks will be called inside of the swift class
 * onAppear. Setup Callbacks will setup all the necessary
 * callbacks for that class.
 */
+ (void)setupCallbacks {
    [self cb_query];
    [self cb_new];
}

/*
 * GetItems takes in a ciphers array with the item type and id.
 * GetItems iterates through the ids and gets the name, and converts
 * the cipherType to itemType and getting the image.
 */
+ (NSArray<ItemElement*>*)getItems:(std::vector<std::pair<ClientWarden::CipherType, std::string>>)ciphers {
    try {
        ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

        NSMutableArray<ItemElement*>* items = [NSMutableArray array];

        for (auto& cipher : ciphers) {
            NSUUID* uuid = [[NSUUID alloc] initWithUUIDString:[NSString stringWithUTF8String: cipher.second.c_str()]];

            std::string c_name;

            v_inst.GetItem(cipher.second)
                 ->GetName(c_name)
                 ->Close();

            NSString* name = [NSString stringWithUTF8String: c_name.c_str()];

            ClientwardenImage* img = nil;

            if (cipher.first == ClientWarden::CipherType::Login) {
                std::vector<std::string> loginUrl;

                v_inst.GetItem<ClientWarden::LoginItem>(cipher.second)
                     ->GetWebsites(loginUrl)
                     ->Close();

                if (loginUrl.size() != 0) {
                    std::optional<std::string> result = v_inst.DownloadIcon(loginUrl[0]);
                    if (result.has_value()) {
                        NSString* path = [NSString stringWithUTF8String: result.value().c_str()];

                        img = [[ClientwardenImage alloc] initWithType:ImageTypeAppSupport path:path];
                    } else {
                        img = [[ClientwardenImage alloc] initWithType:ImageTypeSystemImage path:@"globe"];
                    }
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

            ItemType i_type;
            switch (cipher.first) {
                case ClientWarden::CipherType::Login:
                    i_type = ItemTypeLogin;
                    break;
                case ClientWarden::CipherType::Card:
                    i_type = ItemTypeCard;
                    break;
                case ClientWarden::CipherType::Identity:
                    i_type = ItemTypeIdentity;
                    break;
                case ClientWarden::CipherType::Note:
                    i_type = ItemTypeNote;
                    break;
                case ClientWarden::CipherType::SSHKey:
                    i_type = ItemTypeSSHKey;
                    break;
                default:
                    i_type = ItemTypeLogin;
                    break;
            }

            ItemElement* element = [[ItemElement alloc] initWithName:name uuid:uuid type:i_type image:img];

            [items addObject:element];
        }

        return items;
    } catch (...) {
        dispatch_async(dispatch_get_main_queue(), ^{
            Toast* toast = [[Toast alloc] initWithMessage:@"Failed to Get Items"];
            [[ToastStore instance] addToast:toast];
        });

        NSMutableArray<ItemElement*>* items = [NSMutableArray array];
        return items;
    }
}

/*
 * Query takes in a string and passes back an array of ItemElement
 * with all the items that match the search query
 */
+ (void)cb_query {
    ItemsPanel.instance.cb_query = ^NSArray* _Nonnull(NSString* name) {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();
            ClientWarden::CipherQuery query(v_inst);

            std::string c_name = name.UTF8String;

            std::vector<std::pair<ClientWarden::CipherType, std::string>> ciphers;

            ciphers = v_inst.GetCipherQuery()
                           ->FilterByUnbinned()
                            .FilterNameByRegex(c_name)
                            .GetCiphers();

            return [ItemsPanelBridge getItems:ciphers];
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to query"];
                [[ToastStore instance] addToast:toast];
            });
            
            NSMutableArray<ItemElement*>* items = [NSMutableArray array];
            return items;
        }
    };
}

/*
 * New creates a new item and passes back an item Element
 */
+ (void)cb_new {
    ItemsPanel.instance.cb_new = ^ItemElement* _Nullable(ItemType i_type) {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

            std::shared_ptr<ClientWarden::GenericItem> item;

            ClientwardenImage* img = nil;
            NSString* name = @"New Item";
            
            if (i_type == ItemTypeLogin) {
                item = v_inst.CreateItem<ClientWarden::LoginItem>();
                img = [[ClientwardenImage alloc] initWithType:ImageTypeSystemImage path:@"globe"];
            } else if (i_type == ItemTypeCard) {
                item = v_inst.CreateItem<ClientWarden::CardItem>();
                img = [[ClientwardenImage alloc] initWithType:ImageTypeSystemImage path:@"creditcard"];
            } else if (i_type == ItemTypeIdentity) {
                item = v_inst.CreateItem<ClientWarden::IdentityItem>();
                img = [[ClientwardenImage alloc] initWithType:ImageTypeSystemImage path:@"person.text.rectangle"];
            } else if (i_type == ItemTypeNote) {
                item = v_inst.CreateItem<ClientWarden::NoteItem>();
                img = [[ClientwardenImage alloc] initWithType:ImageTypeSystemImage path:@"pad.header"];
            } else if (i_type == ItemTypeSSHKey) {
                item = v_inst.CreateItem<ClientWarden::SSHKeyItem>();
                img = [[ClientwardenImage alloc] initWithType:ImageTypeSystemImage path:@"key.viewfinder"];
            } else {
                dispatch_async(dispatch_get_main_queue(), ^{
                    Toast* toast = [[Toast alloc] initWithMessage:@"Failed to create new item: Invalid Item Type"];
                    [[ToastStore instance] addToast:toast];
                });

                return nil;
            }

            std::string c_name = "New Item";
            std::string c_uuid = "";

            item->SetName(c_name)
                ->GetId(c_uuid)
                ->Commit();
            
            NSString* s_uuid = [NSString stringWithUTF8String: c_uuid.c_str()];
            NSUUID* uuid = [[NSUUID alloc] initWithUUIDString: s_uuid];

            return [[ItemElement alloc] initWithName:name uuid:uuid type:i_type image:img];
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to create new item"];
                [[ToastStore instance] addToast:toast];
            });

            return nil;
        }
    };
}

@end