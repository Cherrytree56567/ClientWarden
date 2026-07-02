#import "NavPanelBridge.h"
#import <Cocoa/Cocoa.h>
#import "clientwarden-Swift.h"
#include "CipherQuery/CipherQuery.h"
#include "GenericItem/GenericItem.h"
#include "LoginItem/LoginItem.h"
#include "Folder/Folder.h"

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
    [self getFolders];
    [self cb_CreateFolder];
    [self cb_DeleteFolder];
    [self cb_RenameFolder];
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

        ItemElement *element = [[ItemElement alloc] initWithName:name uuid:uuid type:i_type image:img];

        [items addObject:element];
    }

    return items;
}

+ (void)cb_AllItems {
    NavigationPanel.instance.cb_allItems = ^NSArray* _Nonnull {
        ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();
        ClientWarden::CipherQuery query(v_inst);

        std::vector<std::pair<ClientWarden::CipherType, std::string>> ciphers = query.FilterByUnbinned()
                                                                                     .GetCiphers();

        return [NavPanelBridge getItems:ciphers];
    };
}

+ (void)cb_Favorites {
    NavigationPanel.instance.cb_favorites = ^NSArray* _Nonnull {
        ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();
        ClientWarden::CipherQuery query(v_inst);

        std::vector<std::pair<ClientWarden::CipherType, std::string>> ciphers = query.FilterByUnbinned()
                                                                                     .FilterByFavorites()
                                                                                     .GetCiphers();

        return [NavPanelBridge getItems:ciphers];
    };
}

+ (void)cb_Trash {
    NavigationPanel.instance.cb_trash = ^NSArray* _Nonnull {
        ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();
        ClientWarden::CipherQuery query(v_inst);

        std::vector<std::pair<ClientWarden::CipherType, std::string>> ciphers = query.FilterByBinned()
                                                                                     .GetCiphers();

        return [NavPanelBridge getItems:ciphers];
    };
}

+ (void)cb_Login {
    NavigationPanel.instance.cb_login = ^NSArray* _Nonnull {
        ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();
        ClientWarden::CipherQuery query(v_inst);

        std::vector<std::pair<ClientWarden::CipherType, std::string>> ciphers = query.FilterByUnbinned()
                                                                                     .FilterByType(ClientWarden::CipherType::Login)
                                                                                     .GetCiphers();

        return [NavPanelBridge getItems:ciphers];
    };
}

+ (void)cb_Card {
    NavigationPanel.instance.cb_card = ^NSArray* _Nonnull {
        ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();
        ClientWarden::CipherQuery query(v_inst);

        std::vector<std::pair<ClientWarden::CipherType, std::string>> ciphers = query.FilterByUnbinned()
                                                                                     .FilterByType(ClientWarden::CipherType::Card)
                                                                                     .GetCiphers();

        return [NavPanelBridge getItems:ciphers];
    };
}

+ (void)cb_Identity {
    NavigationPanel.instance.cb_identity = ^NSArray* _Nonnull {
        ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();
        ClientWarden::CipherQuery query(v_inst);

        std::vector<std::pair<ClientWarden::CipherType, std::string>> ciphers = query.FilterByUnbinned()
                                                                                     .FilterByType(ClientWarden::CipherType::Identity)
                                                                                     .GetCiphers();

        return [NavPanelBridge getItems:ciphers];
    };
}

+ (void)cb_Note {
    NavigationPanel.instance.cb_note = ^NSArray* _Nonnull {
        ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();
        ClientWarden::CipherQuery query(v_inst);

        std::vector<std::pair<ClientWarden::CipherType, std::string>> ciphers = query.FilterByUnbinned()
                                                                                     .FilterByType(ClientWarden::CipherType::Note)
                                                                                     .GetCiphers();

        return [NavPanelBridge getItems:ciphers];
    };
}

+ (void)cb_SSHKey {
    NavigationPanel.instance.cb_SSHKey = ^NSArray* _Nonnull {
        ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();
        ClientWarden::CipherQuery query(v_inst);

        std::vector<std::pair<ClientWarden::CipherType, std::string>> ciphers = query.FilterByUnbinned()
                                                                                     .FilterByType(ClientWarden::CipherType::SSHKey)
                                                                                     .GetCiphers();

        return [NavPanelBridge getItems:ciphers];
    };
}

+ (void)cb_Folder {
    NavigationPanel.instance.cb_folder = ^NSArray* _Nonnull(NSUUID* uuid) {
        ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();
        ClientWarden::CipherQuery query(v_inst);

        std::string c_uuid = uuid.UUIDString.UTF8String;
        std::transform(c_uuid.begin(), c_uuid.end(), c_uuid.begin(), ::tolower);

        spdlog::info("{}", c_uuid);

        std::vector<std::pair<ClientWarden::CipherType, std::string>> ciphers = query.FilterByUnbinned()
                                                                                     .FilterByFolder(c_uuid)
                                                                                     .GetCiphers();

        return [NavPanelBridge getItems:ciphers];
    };
}

+ (void)getFolders {
    NavigationPanel.instance.cb_getFolders = ^NSArray* _Nonnull {
        ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

        std::vector<std::string> c_folders = v_inst.GetFolders();

        NSMutableArray<Folder*>* folders = [NSMutableArray array];

        for (auto& c_uuid : c_folders) {
            NSString* s_uuid = [NSString stringWithUTF8String: c_uuid.c_str()];

            NSUUID* uuid = [[NSUUID alloc] initWithUUIDString: s_uuid];

            ClientWarden::Folder folder(v_inst, c_uuid);

            std::string c_name;

            folder.GetName(c_name)
                  .Close();
            
            NSString* name = [NSString stringWithUTF8String: c_name.c_str()];

            OPENSSL_cleanse(c_name.data(), c_name.size());
            c_name.clear();
            
            Folder *f = [[Folder alloc] initWithUuid:uuid name:name];
            [folders addObject:f];
        }

        return folders;
    };
}

+ (void)cb_CreateFolder {
    NavigationPanel.instance.cb_createFolder = ^NSUUID* _Nullable(NSString* name) {
        ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

        ClientWarden::Folder folder(v_inst);

        std::string c_name = name.UTF8String;
        std::string c_uuid = folder.SetName(c_name)
                                   .Commit();
        
        if (c_uuid.empty()) {
            return nil;
        }

        return [[NSUUID alloc] initWithUUIDString:[NSString stringWithUTF8String:c_uuid.c_str()]];
    };
}

+ (void)cb_DeleteFolder {
    NavigationPanel.instance.cb_deleteFolder = ^bool(NSUUID* uuid) {
        ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

        std::string c_uuid = uuid.UUIDString.UTF8String;
        std::transform(c_uuid.begin(), c_uuid.end(), c_uuid.begin(), ::tolower);

        if (c_uuid.empty()) {
            return false;
        }

        ClientWarden::Folder folder(v_inst, c_uuid);

        folder.Delete();

        return true;
    };
}

+ (void)cb_RenameFolder {
    NavigationPanel.instance.cb_renameFolder = ^bool(NSUUID *uuid, NSString *name) {
        ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

        std::string c_uuid = uuid.UUIDString.UTF8String;
        std::transform(c_uuid.begin(), c_uuid.end(), c_uuid.begin(), ::tolower);

        if (c_uuid.empty()) {
            return false;
        }

        std::string c_name = name.UTF8String;

        ClientWarden::Folder folder(v_inst, c_uuid);

        folder.SetName(c_name)
              .Commit();

        return true;
    };
}

@end