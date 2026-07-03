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
    [self cb_delete];
    [self cb_restore];
    [self cb_permDel];
    [self cb_sidebar];
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

+ (void)cb_delete {
    SidePanel.instance.cb_delete = ^bool(NSUUID* uuid) {
        ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

        std::string c_uuid = uuid.UUIDString.UTF8String;
        std::transform(c_uuid.begin(), c_uuid.end(), c_uuid.begin(), ::tolower);

        ClientWarden::GenericItem item(v_inst, c_uuid);

        item.Bin();

        return true;
    };
}

+ (void)cb_restore {
    SidePanel.instance.cb_restore = ^bool(NSUUID* uuid) {
        ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

        std::string c_uuid = uuid.UUIDString.UTF8String;
        std::transform(c_uuid.begin(), c_uuid.end(), c_uuid.begin(), ::tolower);

        ClientWarden::GenericItem item(v_inst, c_uuid);

        item.UnBin();

        return true;
    };
}

+ (void)cb_permDel {
    SidePanel.instance.cb_permDel = ^bool(NSUUID* uuid) {
        ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

        std::string c_uuid = uuid.UUIDString.UTF8String;
        std::transform(c_uuid.begin(), c_uuid.end(), c_uuid.begin(), ::tolower);

        ClientWarden::GenericItem item(v_inst, c_uuid);

        item.Delete();

        return true;
    };
}

+ (void)cb_sidebar {
    SidePanel.instance.cb_sidebar = ^bool(NSUUID* uuid) {
        ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

        NSString* name = nil;
        ItemType type = ItemTypeLogin;
        ClientwardenImage* img = nil;
        bool favorite = false;
        NSArray<GenericItemData*>* itemFields = [NSMutableArray array];
        NSArray<FieldItemData*>* customFields = [NSMutableArray array];
        NSArray<NSString*>* itemHistory = [NSMutableArray array];
        NSArray<NSString*>* passwordHistory = [NSMutableArray array];
        NSArray<AttachmentItemData*>* attachments = [NSMutableArray array];
        NSString* notes = nil;

        std::string c_uuid = uuid.UUIDString.UTF8String;
        std::transform(c_uuid.begin(), c_uuid.end(), c_uuid.begin(), ::tolower);

        ClientWarden::GenericItem item(v_inst, c_uuid);

        std::string c_name = "";
        ClientWarden::CipherType c_type;
        std::vector<std::tuple<ClientWarden::CustomFieldType, std::string, std::string>> c_customFields;
        std::string c_creation = "";
        std::string c_modification = "";
        std::string c_deletion = "none";
        std::vector<std::string> c_passwordHistory;
        std::vector<std::string> c_attachIds;
        std::string c_notes;

        item.GetName(c_name)
           ->GetFields(c_customFields)
           ->GetCreation(c_creation)
           ->GetModification(c_modification)
           ->GetDeletion(c_deletion)
           ->GetNotes(c_notes)
           ->GetType(c_type)
           ->GetAttachmentIDs(c_attachIds);
        
        for (auto& c_id : c_attachIds) {
            NSString* id = [NSString stringWithUTF8String: c_id.c_str()];

            std::string c_attach_name;

            item.GetAttachmentName(c_id, c_attach_name);

            NSString* attach_name = [NSString stringWithUTF8String: c_attach_name.c_str()];

            AttachmentItemData* attachment = [[AttachmentItemData alloc] initWithAttachID:id name:attach_name];

            OPENSSL_cleanse(c_attach_name.data(), c_attach_name.size());
            c_attach_name.clear();
            OPENSSL_cleanse(c_id.data(), c_id.size());
            c_id.clear();

            [attachments addObject: attachment];
        }
        
        item.Close();
        
        name = [NSString stringWithUTF8String: c_name.c_str()];

        OPENSSL_cleanse(c_name.data(), c_name.size());
        c_name.clear();

        type = (ItemType)((int)c_type - 1);

        for (auto& field : c_customFields) {
            NSString* title = [NSString stringWithUTF8String: std::get<1>(field).c_str()];
            NSString* value = [NSString stringWithUTF8String: std::get<2>(field).c_str()];
            FieldItemType type = (FieldItemType)((int)std::get<0>(field));

            FieldItemData* fieldItem = [[FieldItemData alloc] initWithTitle:title value:value type:type];
            [customFields addObject:fieldItem];
            OPENSSL_cleanse(std::get<1>(field).data(), std::get<1>(field).size());
            std::get<1>(field).clear();
            OPENSSL_cleanse(std::get<2>(field).data(), std::get<2>(field).size());
            std::get<2>(field).clear();
        }

        NSString* creation = [NSString stringWithFormat:@"Creation: %s", c_creation.c_str()];
        [itemHistory addObject: creation];

        NSString* modification = [NSString stringWithFormat:@"Modification: %s", c_modification.c_str()];
        [itemHistory addObject: modification];

        if (c_deletion != "none") {
            NSString* deletion = [NSString stringWithFormat:@"Deletion: %s", c_deletion.c_str()];
            [itemHistory addObject: deletion];
        }

        notes = [NSString stringWithUTF8String: c_notes.c_str()];

        OPENSSL_cleanse(c_notes.data(), c_notes.size());
        c_notes.clear();

        if (c_type == ClientWarden::CipherType::Login) {
            ClientWarden::LoginItem l_item(v_inst, c_uuid);

            std::string c_username = "";
            std::string c_password = "";
            std::string c_totp = "";
            std::vector<std::string> c_website;
            std::vector<std::pair<std::time_t, std::string>> c_passHist;

            l_item.GetUsername(c_username)
                 ->GetPassword(c_password)
                 ->GetTotpSecret(c_totp)
                 ->GetWebsites(c_website)
                 ->GetPasswordHistory(c_passHist)
                 ->Close();

            NSString* username = [NSString stringWithUTF8String: c_username.c_str()];
            NSString* password = [NSString stringWithUTF8String: c_password.c_str()];
            NSString* totp = [NSString stringWithUTF8String: c_totp.c_str()];

            GenericItemData* usernameItem = [[GenericItemData alloc] initWithTitle: @"Username"
                                                                     value: username
                                                                     type:GenericItemTypeGeneric];

            GenericItemData* passwordItem = [[GenericItemData alloc] initWithTitle: @"Password"
                                                                     value: password
                                                                     type:GenericItemTypePassword];
            
            auto cc_uuid = c_uuid;

            GenericItemData* totpItem = [[GenericItemData alloc] initWithTitle: @"Two Factor Authentication"
                                                                 value: totp
                                                                 type:GenericItemTypeTotp
            cb_getTOTP:^TOTPResult * _Nonnull {
                ClientWarden::LoginItem loginItem(v_inst, cc_uuid);

                ClientWarden::TOTPCode code;

                loginItem.GetTotp(code)
                        ->Close();
                
                int64_t refreshDate = (int64_t)code.remaining;
                NSInteger maxTimer = (NSInteger)code.period;
                NSString* codeValue = [NSString stringWithUTF8String: code.code.c_str()];

                return [[TOTPResult alloc] initWithRefreshDate:refreshDate maxTimer:maxTimer value:codeValue];
            }];

            NSMutableArray<NSString*>* websitesArray = [NSMutableArray arrayWithCapacity: c_website.size()];

            if (c_website.size() != 0) {
                std::string c_path = v_inst.downloadIcon(c_website[0]);
                NSString* path = [NSString stringWithUTF8String: c_path.c_str()];

                img = [[ClientwardenImage alloc] initWithType:ImageTypeAppSupport path:path];
            } else {
                img = [[ClientwardenImage alloc] initWithType:ImageTypeSystemImage path:@"globe"];
            }

            for (auto& c_site : c_website) {
                NSString* site = [NSString stringWithUTF8String: c_site.c_str()];
                [websitesArray addObject: site];
                OPENSSL_cleanse(c_site.data(), c_site.size());
                c_site.clear();
            }

            NSString* websites = [websitesArray componentsJoinedByString:@"\n"];

            GenericItemData* websiteItem = [[GenericItemData alloc] initWithTitle: @"Websites"
                                                                     value: websites
                                                                     type:GenericItemTypeWebsite];
            
            [itemFields addObject: usernameItem];
            [itemFields addObject: passwordItem];
            [itemFields addObject: totpItem];
            [itemFields addObject: websiteItem];

            passwordHistory = [NSMutableArray arrayWithCapacity: c_passHist.size()];
            for (auto& c_pass : c_passHist) {
                NSString* pass = [NSString stringWithUTF8String: c_pass.second.c_str()];
                [passwordHistory addObject: pass];
                OPENSSL_cleanse(c_pass.second.data(), c_pass.second.size());
                c_pass.second.clear();
            }
            
            OPENSSL_cleanse(c_username.data(), c_username.size());
            c_username.clear();
            OPENSSL_cleanse(c_password.data(), c_password.size());
            c_password.clear();
            OPENSSL_cleanse(c_totp.data(), c_totp.size());
            c_totp.clear();
        }/* else if (c_type == ClientWarden::CipherType::Card) {
            ClientWarden::CardItem l_item(v_inst, c_uuid);

            std::string c_brand = "";
            std::string c_cardholderName = "";
            std::string c_totp = "";
            std::vector<std::string> c_website;
            std::vector<std::pair<std::time_t, std::string>> c_passHist;

            l_item.GetUsername(c_username)
                 ->GetPassword(c_password)
                 ->GetTotpSecret(c_totp)
                 ->GetWebsites(c_website)
                 ->GetPasswordHistory(c_passHist)
                 ->Close();

            NSString* username = [NSString stringWithUTF8String: c_username.c_str()];
            NSString* password = [NSString stringWithUTF8String: c_password.c_str()];
            NSString* totp = [NSString stringWithUTF8String: c_totp.c_str()];

            GenericItemData* usernameItem = [[GenericItemData alloc] initWithTitle: @"Username"
                                                                     value: username
                                                                     type:GenericItemTypeGeneric];

            GenericItemData* passwordItem = [[GenericItemData alloc] initWithTitle: @"Password"
                                                                     value: password
                                                                     type:GenericItemTypePassword];
            
            OPENSSL_cleanse(c_username.data(), c_username.size());
            c_username.clear();
            OPENSSL_cleanse(c_password.data(), c_password.size());
            c_password.clear();
            OPENSSL_cleanse(c_totp.data(), c_totp.size());
            c_totp.clear();
        }*/

        [SidePanel.instance viewItemWithName:name uuid:uuid type:type icon:img favorite:favorite itemFields:itemFields 
                            customFields:customFields itemHistory:itemHistory passwordHistory:passwordHistory 
                            attachmentItems:attachments notes:notes];

        return true;
    };
}

@end