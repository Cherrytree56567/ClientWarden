#import "NavPanelBridge.h"
#import <Cocoa/Cocoa.h>
#import "clientwarden-Swift.h"
#include "CipherQuery/CipherQuery.h"
#include "GenericItem/GenericItem.h"
#include "LoginItem/LoginItem.h"
#include "Folder/Folder.h"
#include "Vault.h"

#include <chrono>

@implementation NavPanelBridge

/*
 * Setup Callbacks will be called inside of the swift class
 * onAppear. Setup Callbacks will setup all the necessary
 * callbacks for that class.
 */
+ (void)setupCallbacks {
    [self cb_AllItems];
    [self cb_Favorites];
    [self cb_Trash];
    [self cb_archived];
    [self cb_Login];
    [self cb_Card];
    [self cb_Identity];
    [self cb_Note];
    [self cb_SSHKey];
    [self cb_Folder];
    [self getFolders];
    [self cb_CreateFolder];
    [self cb_DeleteFolder];
    [self cb_RenameFolder];
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
            } else {
                img = [[ClientwardenImage alloc] initWithType:ImageTypeSystemImage path:@"questionmark.app.dashed"];
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

            ItemElement *element = [[ItemElement alloc] initWithName:name uuid:uuid type:i_type image:img];

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
 * All of the callbacks below use CipherQuery and pass it to
 * get Items and return an array of ItemElement's
 */
+ (void)cb_AllItems {
    NavigationPanel.instance.cb_allItems = ^NSArray* _Nonnull {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

            std::vector<std::pair<ClientWarden::CipherType, std::string>> ciphers;
            
            ciphers = v_inst.GetCipherQuery()
                           ->FilterByUnbinned()
                            .FilterByUnarchived()
                            .GetCiphers();
            
            NSArray<ItemElement*>* items = [NavPanelBridge getItems:ciphers];

            return items;
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to Get All Items"];
                [[ToastStore instance] addToast:toast];
            });

            NSMutableArray<ItemElement*>* items = [NSMutableArray array];
            return items;
        }
    };
}

+ (void)cb_Favorites {
    NavigationPanel.instance.cb_favorites = ^NSArray* _Nonnull {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

            std::vector<std::pair<ClientWarden::CipherType, std::string>> ciphers;
            
            ciphers = v_inst.GetCipherQuery()
                           ->FilterByUnbinned()
                            .FilterByUnarchived()
                            .FilterByFavorites()
                            .GetCiphers();

            return [NavPanelBridge getItems:ciphers];
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to Get Favorites"];
                [[ToastStore instance] addToast:toast];
            });

            NSMutableArray<ItemElement*>* items = [NSMutableArray array];
            return items;
        }
    };
}

+ (void)cb_Trash {
    NavigationPanel.instance.cb_trash = ^NSArray* _Nonnull {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

            std::vector<std::pair<ClientWarden::CipherType, std::string>> ciphers;
            
            ciphers = v_inst.GetCipherQuery()
                           ->FilterByBinned()
                            .GetCiphers();

            return [NavPanelBridge getItems:ciphers];
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to Get Trash Items"];
                [[ToastStore instance] addToast:toast];
            });

            NSMutableArray<ItemElement*>* items = [NSMutableArray array];
            return items;
        }
    };
}

+ (void)cb_archived {
    NavigationPanel.instance.cb_archived = ^NSArray* _Nonnull {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

            std::vector<std::pair<ClientWarden::CipherType, std::string>> ciphers;
            
            ciphers = v_inst.GetCipherQuery()
                           ->FilterByUnbinned()
                            .FilterByArchived()
                            .GetCiphers();

            return [NavPanelBridge getItems:ciphers];
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to Get Trash Items"];
                [[ToastStore instance] addToast:toast];
            });

            NSMutableArray<ItemElement*>* items = [NSMutableArray array];
            return items;
        }
    };
}

+ (void)cb_Login {
    NavigationPanel.instance.cb_login = ^NSArray* _Nonnull {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

            std::vector<std::pair<ClientWarden::CipherType, std::string>> ciphers;
            
            ciphers = v_inst.GetCipherQuery()
                           ->FilterByUnbinned()
                            .FilterByUnarchived()
                            .FilterByType(ClientWarden::CipherType::Login)
                            .GetCiphers();

            return [NavPanelBridge getItems:ciphers];
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to Get Login Items"];
                [[ToastStore instance] addToast:toast];
            });

            NSMutableArray<ItemElement*>* items = [NSMutableArray array];
            return items;
        }
    };
}

+ (void)cb_Card {
    NavigationPanel.instance.cb_card = ^NSArray* _Nonnull {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

            std::vector<std::pair<ClientWarden::CipherType, std::string>> ciphers;
            
            ciphers = v_inst.GetCipherQuery()
                           ->FilterByUnbinned()
                            .FilterByUnarchived()
                            .FilterByType(ClientWarden::CipherType::Card)
                            .GetCiphers();

            return [NavPanelBridge getItems:ciphers];
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to Get Card Items"];
                [[ToastStore instance] addToast:toast];
            });

            NSMutableArray<ItemElement*>* items = [NSMutableArray array];
            return items;
        }
    };
}

+ (void)cb_Identity {
    NavigationPanel.instance.cb_identity = ^NSArray* _Nonnull {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

            std::vector<std::pair<ClientWarden::CipherType, std::string>> ciphers;
            
            ciphers = v_inst.GetCipherQuery()
                           ->FilterByUnbinned()
                            .FilterByUnarchived()
                            .FilterByType(ClientWarden::CipherType::Identity)
                            .GetCiphers();

            return [NavPanelBridge getItems:ciphers];
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to Get Identity Items"];
                [[ToastStore instance] addToast:toast];
            });

            NSMutableArray<ItemElement*>* items = [NSMutableArray array];
            return items;
        }
    };
}

+ (void)cb_Note {
    NavigationPanel.instance.cb_note = ^NSArray* _Nonnull {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

            std::vector<std::pair<ClientWarden::CipherType, std::string>> ciphers;
            
            ciphers = v_inst.GetCipherQuery()
                           ->FilterByUnbinned()
                            .FilterByUnarchived()
                            .FilterByType(ClientWarden::CipherType::Note)
                            .GetCiphers();

            return [NavPanelBridge getItems:ciphers];
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to Get Note Items"];
                [[ToastStore instance] addToast:toast];
            });

            NSMutableArray<ItemElement*>* items = [NSMutableArray array];
            return items;
        }
    };
}

+ (void)cb_SSHKey {
    NavigationPanel.instance.cb_SSHKey = ^NSArray* _Nonnull {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

            std::vector<std::pair<ClientWarden::CipherType, std::string>> ciphers;
            
            ciphers = v_inst.GetCipherQuery()
                           ->FilterByUnbinned()
                            .FilterByUnarchived()
                            .FilterByType(ClientWarden::CipherType::SSHKey)
                            .GetCiphers();

            return [NavPanelBridge getItems:ciphers];
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to Get SSH Key Items"];
                [[ToastStore instance] addToast:toast];
            });

            NSMutableArray<ItemElement*>* items = [NSMutableArray array];
            return items;
        }
    };
}

+ (void)cb_Folder {
    NavigationPanel.instance.cb_folder = ^NSArray* _Nonnull(NSUUID* uuid) {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

            std::vector<std::pair<ClientWarden::CipherType, std::string>> ciphers;

            std::string c_uuid = uuid.UUIDString.UTF8String;
            std::transform(c_uuid.begin(), c_uuid.end(), c_uuid.begin(), ::tolower);

            if (c_uuid.empty()) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    Toast* toast = [[Toast alloc] initWithMessage:@"Empty UUID"];
                    [[ToastStore instance] addToast:toast];
                });

                NSMutableArray<ItemElement*>* items = [NSMutableArray array];
                return items;
            }
            
            ciphers = v_inst.GetCipherQuery()
                           ->FilterByUnbinned()
                            .FilterByUnarchived()
                            .FilterByFolder(c_uuid)
                            .GetCiphers();

            return [NavPanelBridge getItems:ciphers];
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to Get Folder Items"];
                [[ToastStore instance] addToast:toast];
            });

            NSMutableArray<ItemElement*>* items = [NSMutableArray array];
            return items;
        }
    };
}

+ (void)getFolders {
    NavigationPanel.instance.cb_getFolders = ^NSArray* _Nonnull {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

            std::vector<std::string> c_folders = v_inst.GetFolders();

            NSMutableArray<Folder*>* folders = [NSMutableArray array];

            NSUUID* emptyUUID = [[NSUUID alloc] initWithUUIDString:@"00000000-0000-0000-0000-000000000000"];
            Folder* emptyFolder = [[Folder alloc] initWithUuid:emptyUUID name:@""];
            [folders addObject:emptyFolder];

            for (auto& c_uuid : c_folders) {
                NSString* s_uuid = [NSString stringWithUTF8String: c_uuid.c_str()];

                NSUUID* uuid = [[NSUUID alloc] initWithUUIDString: s_uuid];

                std::string c_name;

                v_inst.GetFolder(c_uuid)
                     ->GetName(c_name)
                      .Close();
                
                NSString* name = [NSString stringWithUTF8String: c_name.c_str()];

                OPENSSL_cleanse(c_name.data(), c_name.size());
                c_name.clear();
                
                Folder* f = [[Folder alloc] initWithUuid:uuid name:name];
                [folders addObject:f];
            }

            return folders;
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to Get Folders"];
                [[ToastStore instance] addToast:toast];
            });

            NSMutableArray<Folder*>* items = [NSMutableArray array];
            return items;
        }
    };
}

/*
 * CreateFolder uses a name and creates a folder and passes back a UUID
 */
+ (void)cb_CreateFolder {
    NavigationPanel.instance.cb_createFolder = ^NSUUID* _Nullable(NSString* name) {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

            std::string c_name = name.UTF8String;
            std::string c_uuid = v_inst.CreateFolder()
                                      ->SetName(c_name)
                                       .Commit();
            
            if (c_uuid.empty()) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    Toast* toast = [[Toast alloc] initWithMessage:@"Unable to create folder offline"];
                    [[ToastStore instance] addToast:toast];
                });
                return nil;
            }

            return [[NSUUID alloc] initWithUUIDString:[NSString stringWithUTF8String:c_uuid.c_str()]];
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to Create Folder"];
                [[ToastStore instance] addToast:toast];
            });

            return nil;
        }
    };
}

/*
 * DeleteFolder uses a UUID and passes back a result bool
 */
+ (void)cb_DeleteFolder {
    NavigationPanel.instance.cb_deleteFolder = ^BOOL(NSUUID* uuid) {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

            std::string c_uuid = uuid.UUIDString.UTF8String;
            std::transform(c_uuid.begin(), c_uuid.end(), c_uuid.begin(), ::tolower);

            if (c_uuid.empty()) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    Toast* toast = [[Toast alloc] initWithMessage:@"Empty UUID"];
                    [[ToastStore instance] addToast:toast];
                });
                return NO;
            }

            v_inst.GetFolder(c_uuid)
                 ->Delete();

            return YES;
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to Delete Folder"];
                [[ToastStore instance] addToast:toast];
            });

            return NO;
        }
    };
}

/*
 * RenameFolder uses a UUID and name and passes back a result bool
 */
+ (void)cb_RenameFolder {
    NavigationPanel.instance.cb_renameFolder = ^BOOL(NSUUID *uuid, NSString *name) {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

            std::string c_uuid = uuid.UUIDString.UTF8String;
            std::transform(c_uuid.begin(), c_uuid.end(), c_uuid.begin(), ::tolower);

            if (c_uuid.empty()) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    Toast* toast = [[Toast alloc] initWithMessage:@"Empty UUID"];
                    [[ToastStore instance] addToast:toast];
                });
                return NO;
            }

            std::string c_name = name.UTF8String;

            v_inst.GetFolder(c_uuid)
                 ->SetName(c_name)
                  .Commit();

            return YES;
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to Rename Folder"];
                [[ToastStore instance] addToast:toast];
            });

            return NO;
        }
    };
}

@end