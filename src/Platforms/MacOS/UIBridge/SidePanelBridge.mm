#import "SidePanelBridge.h"
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

@implementation SidePanelBridge

+ (void)setupCallbacks {
    [self cb_favorite];
    [self cb_duplicate];
}

+ (void)cb_favorite {
    SidePanel.instance.cb_favorite = ^bool(bool fav, NSUUID* uuid) {
        ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

        std::string c_uuid = uuid.UUIDString.UTF8String;
        std::transform(c_uuid.begin(), c_uuid.end(), c_uuid.begin(), ::tolower);

        ClientWarden::GenericItem item(v_inst, c_uuid);

        item.SetFavorite(fav)
           ->Commit();

        return true;
    };
}

+ (void)cb_duplicate {
    SidePanel.instance.cb_duplicate = ^ItemElement* _Nonnull(NSUUID* uuid, ItemType i_type) {
        ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

        std::string c_uuid = uuid.UUIDString.UTF8String;
        std::transform(c_uuid.begin(), c_uuid.end(), c_uuid.begin(), ::tolower);

        std::string c_dupUUID = "";
        std::string c_name = "";
        ClientwardenImage* img = nil;

        if (i_type == ItemTypeLogin) {
            ClientWarden::LoginItem item(v_inst, c_uuid);

            std::vector<std::string> loginUrl;

            item.GetWebsites(loginUrl)
               ->GetName(c_name)
               ->Duplicate(c_dupUUID)
               ->Close();
            
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
        } else if (i_type == ItemTypeCard) {
            ClientWarden::CardItem item(v_inst, c_uuid);

            item.GetName(c_name)
               ->Duplicate(c_dupUUID)
               ->Close();
            
            img = [[ClientwardenImage alloc] initWithType:ImageTypeSystemImage path:@"creditcard"];
        } else if (i_type == ItemTypeIdentity) {
            ClientWarden::IdentityItem item(v_inst, c_uuid);

            item.GetName(c_name)
               ->Duplicate(c_dupUUID)
               ->Close();
            
            img = [[ClientwardenImage alloc] initWithType:ImageTypeSystemImage path:@"person.text.rectangle"];
        } else if (i_type == ItemTypeNote) {
            ClientWarden::NoteItem item(v_inst, c_uuid);

            item.GetName(c_name)
               ->Duplicate(c_dupUUID)
               ->Close();
            
            img = [[ClientwardenImage alloc] initWithType:ImageTypeSystemImage path:@"pad.header"];
        } else if (i_type == ItemTypeSSHKey) {
            ClientWarden::SSHKeyItem item(v_inst, c_uuid);

            item.GetName(c_name)
               ->Duplicate(c_dupUUID)
               ->Close();
            
            img = [[ClientwardenImage alloc] initWithType:ImageTypeSystemImage path:@"key.viewfinder"];
        }

        NSString* name = [NSString stringWithUTF8String: c_name.c_str()];

        OPENSSL_cleanse(c_name.data(), c_name.size());
        c_name.clear();

        NSUUID* dupUUID = [[NSUUID alloc] initWithUUIDString: [NSString stringWithUTF8String: c_dupUUID.c_str()]];

        return [[ItemElement alloc] initWithName:name uuid:dupUUID type:i_type image:img];
    };
}

@end