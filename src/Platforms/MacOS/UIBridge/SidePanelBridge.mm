#import "SidePanelBridge.h"
#import <Cocoa/Cocoa.h>
#import "clientwarden-Swift.h"
#include <boost/algorithm/string.hpp>
#include "CipherQuery/CipherQuery.h"
#include "GenericItem/GenericItem.h"
#include "LoginItem/LoginItem.h"
#include "CardItem/CardItem.h"
#include "IdentityItem/IdentityItem.h"
#include "NoteItem/NoteItem.h"
#include "SSHKeyItem/SSHKeyItem.h"
#include "Folder/Folder.h"
#include "PasswordGenerator/PasswordGenerator.h"
#include "Vault.h"

@implementation SidePanelBridge

/*
 * Setup Callbacks will be called inside of the swift class
 * onAppear. Setup Callbacks will setup all the necessary
 * callbacks for that class.
 */
+ (void)setupCallbacks {
    [self cb_favorite];
    [self cb_duplicate];
    [self cb_delete];
    [self cb_restore];
    [self cb_permDel];
    [self cb_archive];
    [self cb_unarchive];
    [self cb_deleteMultiple];
    [self cb_restoreMultiple];
    [self cb_permDelMultiple];
    [self cb_archiveMultiple];
    [self cb_unarchiveMultiple];
    [self cb_sidebar];
    [self cb_downloadAttachment];
    [self cb_uploadAttachment];
    [self cb_removeAttachment];
    [self cb_save];
    [self cb_genRandPasswd];
    [self cb_genSimplPasswd];
    [self cb_genPinPasswd];
}

/*
 * Favorite uses a bool and a UUID to apply favorite status to an item
 */
+ (void)cb_favorite {
    SidePanel.instance.cb_favorite = ^BOOL(BOOL fav, NSUUID* uuid) {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

            std::string c_uuid = uuid.UUIDString.UTF8String;
            std::transform(c_uuid.begin(), c_uuid.end(), c_uuid.begin(), ::tolower);

            v_inst.GetItem(c_uuid)
                 ->SetFavorite((bool)fav)
                 ->Commit();

            return YES;
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to Favorite Item"];
                [[ToastStore instance] addToast:toast];
            });
            
            return NO;
        }
    };
}

/*
 * Duplicate duplicates and item with a UUID and ItemType and passes back
 * an ItemType to be added to the Items Panel
 */
+ (void)cb_duplicate {
    SidePanel.instance.cb_duplicate = ^ItemElement* _Nonnull(NSUUID* uuid, ItemType i_type) {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

            std::string c_uuid = uuid.UUIDString.UTF8String;
            std::transform(c_uuid.begin(), c_uuid.end(), c_uuid.begin(), ::tolower);

            std::string c_dupUUID = "";
            std::string c_name = "";
            ClientwardenImage* img = nil;

            if (i_type == ItemTypeLogin) {
                std::vector<std::string> loginUrl;

                v_inst.GetItem<ClientWarden::LoginItem>(c_uuid)
                     ->GetWebsites(loginUrl)
                     ->GetName(c_name)
                     ->Duplicate(c_dupUUID)
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
            } else if (i_type == ItemTypeCard) {
                v_inst.GetItem<ClientWarden::CardItem>(c_uuid)
                     ->GetName(c_name)
                     ->Duplicate(c_dupUUID)
                     ->Close();
                
                img = [[ClientwardenImage alloc] initWithType:ImageTypeSystemImage path:@"creditcard"];
            } else if (i_type == ItemTypeIdentity) {
                v_inst.GetItem<ClientWarden::IdentityItem>(c_uuid)
                     ->GetName(c_name)
                     ->Duplicate(c_dupUUID)
                     ->Close();
                
                img = [[ClientwardenImage alloc] initWithType:ImageTypeSystemImage path:@"person.text.rectangle"];
            } else if (i_type == ItemTypeNote) {
                v_inst.GetItem<ClientWarden::NoteItem>(c_uuid)
                     ->GetName(c_name)
                     ->Duplicate(c_dupUUID)
                     ->Close();
                
                img = [[ClientwardenImage alloc] initWithType:ImageTypeSystemImage path:@"pad.header"];
            } else if (i_type == ItemTypeSSHKey) {
                v_inst.GetItem<ClientWarden::SSHKeyItem>(c_uuid)
                     ->GetName(c_name)
                     ->Duplicate(c_dupUUID)
                     ->Close();
                
                img = [[ClientwardenImage alloc] initWithType:ImageTypeSystemImage path:@"key.viewfinder"];
            }

            NSString* name = [NSString stringWithUTF8String: c_name.c_str()];

            OPENSSL_cleanse(c_name.data(), c_name.size());
            c_name.clear();

            NSUUID* dupUUID = [[NSUUID alloc] initWithUUIDString: [NSString stringWithUTF8String: c_dupUUID.c_str()]];

            return [[ItemElement alloc] initWithName:name uuid:dupUUID type:i_type image:img];
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to Duplicate Item"];
                [[ToastStore instance] addToast:toast];
            });

            return nil;
        }
    };
}

/*
 * Delete moves the item with the UUID in the bin and passes back a result bool
 */
+ (void)cb_delete {
    SidePanel.instance.cb_delete = ^BOOL(NSUUID* uuid) {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

            std::string c_uuid = uuid.UUIDString.UTF8String;
            std::transform(c_uuid.begin(), c_uuid.end(), c_uuid.begin(), ::tolower);

            v_inst.GetItem(c_uuid)
                 ->Bin();

            return YES;
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to Delete Item"];
                [[ToastStore instance] addToast:toast];
            });

            return NO;
        }
    };
}

/*
 * Restore moves the item with the UUID out of the bin and passes back a result bool
 */
+ (void)cb_restore {
    SidePanel.instance.cb_restore = ^BOOL(NSUUID* uuid) {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

            std::string c_uuid = uuid.UUIDString.UTF8String;
            std::transform(c_uuid.begin(), c_uuid.end(), c_uuid.begin(), ::tolower);

            v_inst.GetItem(c_uuid)
                 ->UnBin();

            return YES;
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to Restore Item"];
                [[ToastStore instance] addToast:toast];
            });

            return NO;
        }
    };
}

/*
 * Archive moves the item with the UUID to the Archive and passes back a result bool
 */
+ (void)cb_archive {
    SidePanel.instance.cb_archive = ^BOOL(NSUUID* uuid) {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

            std::string c_uuid = uuid.UUIDString.UTF8String;
            std::transform(c_uuid.begin(), c_uuid.end(), c_uuid.begin(), ::tolower);

            v_inst.GetItem(c_uuid)
                 ->Archive();

            return YES;
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to Archive Item"];
                [[ToastStore instance] addToast:toast];
            });

            return NO;
        }
    };
}

/*
 * UnArchive moves the item with the UUID out of the Archive and passes back a result bool
 */
+ (void)cb_unarchive {
    SidePanel.instance.cb_unarchive = ^BOOL(NSUUID* uuid) {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

            std::string c_uuid = uuid.UUIDString.UTF8String;
            std::transform(c_uuid.begin(), c_uuid.end(), c_uuid.begin(), ::tolower);

            v_inst.GetItem(c_uuid)
                 ->UnArchive();

            return YES;
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to UnArchive Item"];
                [[ToastStore instance] addToast:toast];
            });

            return NO;
        }
    };
}

/*
 * Permanantly Delete deletes the item with the UUID and passes back a result bool
 */
+ (void)cb_permDel {
    SidePanel.instance.cb_permDel = ^BOOL(NSUUID* uuid) {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

            std::string c_uuid = uuid.UUIDString.UTF8String;
            std::transform(c_uuid.begin(), c_uuid.end(), c_uuid.begin(), ::tolower);

            v_inst.GetItem(c_uuid)
                 ->Delete();

            return YES;
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to Permanently Delete Item"];
                [[ToastStore instance] addToast:toast];
            });

            return NO;
        }
    };
}

/*
 * cb_deleteMultiple takes in an array of uuid, and bin's them each. It doesn't
 * use an api to delete them all at once, bc Im too lazy and it would cause issues
 * bc of the way things are structured.
 */
+ (void)cb_deleteMultiple {
    SidePanel.instance.cb_deleteMultiple = ^BOOL(NSArray<NSUUID*>* _Nonnull uuids) {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

            for (NSUUID* uuid in uuids) {
                std::string c_uuid = uuid.UUIDString.UTF8String;
                std::transform(c_uuid.begin(), c_uuid.end(), c_uuid.begin(), ::tolower);

                v_inst.GetItem(c_uuid)
                    ->Bin();
            }

            return YES;
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to Delete Items"];
                [[ToastStore instance] addToast:toast];
            });

            return NO;
        }
    };
}

/*
 * cb_restoreMultiple takes in an array of UUID's and restores each one of them and
 * then returns true
 */
+ (void)cb_restoreMultiple {
    SidePanel.instance.cb_restoreMultiple = ^BOOL(NSArray<NSUUID*>* _Nonnull uuids) {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

            for (NSUUID* uuid in uuids) {
                std::string c_uuid = uuid.UUIDString.UTF8String;
                std::transform(c_uuid.begin(), c_uuid.end(), c_uuid.begin(), ::tolower);

                v_inst.GetItem(c_uuid)
                    ->UnBin();
            }

            return YES;
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to Restore Items"];
                [[ToastStore instance] addToast:toast];
            });

            return NO;
        }
    };
}

/*
 * cb_permDelMultiple takes in an array of UUID's and permanantly deletes each one of 
 * them and then returns true
 */
+ (void)cb_permDelMultiple {
    SidePanel.instance.cb_permDelMultiple = ^BOOL(NSArray<NSUUID*>* _Nonnull uuids) {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

            for (NSUUID* uuid in uuids) {
                std::string c_uuid = uuid.UUIDString.UTF8String;
                std::transform(c_uuid.begin(), c_uuid.end(), c_uuid.begin(), ::tolower);

                v_inst.GetItem(c_uuid)
                    ->Delete();
            }

            return YES;
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to Permanantly Delete Items"];
                [[ToastStore instance] addToast:toast];
            });

            return NO;
        }
    };
}

/*
 * cb_archiveMultiple takes in an array of UUID's and archives each one of them and
 * then returns true
 */
+ (void)cb_archiveMultiple {
    SidePanel.instance.cb_archiveMultiple = ^BOOL(NSArray<NSUUID*>* _Nonnull uuids) {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

            for (NSUUID* uuid in uuids) {
                std::string c_uuid = uuid.UUIDString.UTF8String;
                std::transform(c_uuid.begin(), c_uuid.end(), c_uuid.begin(), ::tolower);

                v_inst.GetItem(c_uuid)
                    ->Archive();
            }

            return YES;
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to Archive Items"];
                [[ToastStore instance] addToast:toast];
            });

            return NO;
        }
    };
}

/*
 * Unarchive Multiple takes in an array of UUID's and archives each one of them and
 * then returns true
 */
+ (void)cb_unarchiveMultiple {
    SidePanel.instance.cb_unarchiveMultiple = ^BOOL(NSArray<NSUUID*>* _Nonnull uuids) {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

            for (NSUUID* uuid in uuids) {
                std::string c_uuid = uuid.UUIDString.UTF8String;
                std::transform(c_uuid.begin(), c_uuid.end(), c_uuid.begin(), ::tolower);

                v_inst.GetItem(c_uuid)
                    ->UnArchive();
            }

            return YES;
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to Unarchive Items"];
                [[ToastStore instance] addToast:toast];
            });

            return NO;
        }
    };
}

/*
 * Sidebar fills the SidePanel with the item's info using a UUID
 * and passes back a result bool
 */
static bool sidebar(NSUUID* uuid) {
    try {
        ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

        NSString* name = nil;
        ItemType type = ItemTypeLogin;
        ClientwardenImage* img = [[ClientwardenImage alloc] initWithType:ImageTypeSystemImage path:@"questionmark.app.dashed"];
        NSUUID* folderUUID = nil;
        bool favorite = false;
        bool reprompt = false;
        NSArray<GenericItemData*>* itemFields = [NSMutableArray array];
        NSArray<FieldItemData*>* customFields = [NSMutableArray array];
        NSArray<NSString*>* itemHistory = [NSMutableArray array];
        NSArray<PasswordHistoryItem*>* passwordHistory = [NSMutableArray array];
        NSArray<AttachmentItemData*>* attachments = [NSMutableArray array];
        NSString* notes = nil;

        std::string c_uuid = uuid.UUIDString.UTF8String;
        std::transform(c_uuid.begin(), c_uuid.end(), c_uuid.begin(), ::tolower);

        std::shared_ptr<ClientWarden::GenericItem> item = v_inst.GetItem(c_uuid);

        std::string c_name = "";
        std::string c_folderID = "00000000-0000-0000-0000-000000000000";
        ClientWarden::CipherType c_type;
        std::vector<std::tuple<ClientWarden::CustomFieldType, std::string, std::string>> c_customFields;
        std::string c_creation = "";
        std::string c_modification = "";
        std::string c_deletion = "none";
        std::vector<std::string> c_passwordHistory;
        std::vector<std::string> c_attachIds;
        std::string c_notes;

        item->GetName(c_name)
            ->GetReprompt(reprompt)
            ->GetFolder(c_folderID)
            ->GetFavorite(favorite)
            ->GetFields(c_customFields)
            ->GetCreation(c_creation)
            ->GetModification(c_modification)
            ->GetDeletion(c_deletion)
            ->GetNotes(c_notes)
            ->GetType(c_type)
            ->GetAttachmentIDs(c_attachIds);
            
        NSString* s_folderUUID = [NSString stringWithUTF8String: c_folderID.c_str()];
        folderUUID = [[NSUUID alloc] initWithUUIDString: s_folderUUID];
            
        for (auto& c_id : c_attachIds) {
            NSString* id = [NSString stringWithUTF8String: c_id.c_str()];

            std::string c_attach_name;

            item->GetAttachmentName(c_id, c_attach_name);

            NSString* attach_name = [NSString stringWithUTF8String: c_attach_name.c_str()];

            AttachmentItemData* attachment = [[AttachmentItemData alloc] initWithAttachID:id name:attach_name];

            OPENSSL_cleanse(c_attach_name.data(), c_attach_name.size());
            c_attach_name.clear();
            OPENSSL_cleanse(c_id.data(), c_id.size());
            c_id.clear();

            [attachments addObject: attachment];
        }
            
        item->Close();
            
        name = [NSString stringWithUTF8String: c_name.c_str()];

        OPENSSL_cleanse(c_name.data(), c_name.size());
        c_name.clear();

        switch (c_type) {
            case ClientWarden::CipherType::Login:
                type = ItemTypeLogin;
                break;
            case ClientWarden::CipherType::Card:
                type = ItemTypeCard;
                break;
            case ClientWarden::CipherType::Identity:
                type = ItemTypeIdentity;
                break;
            case ClientWarden::CipherType::Note:
                type = ItemTypeNote;
                break;
            case ClientWarden::CipherType::SSHKey:
                type = ItemTypeSSHKey;
                break;
            default:
                type = ItemTypeLogin;
                break;
        }

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
            std::string c_username = "";
            std::string c_password = "";
            std::string c_totp = "";
            std::vector<std::string> c_website;
            std::vector<std::pair<std::time_t, std::string>> c_passHist;

            v_inst.GetItem<ClientWarden::LoginItem>(c_uuid)
                 ->GetUsername(c_username)
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
                ClientWarden::TOTPCode code;

                v_inst.GetItem<ClientWarden::LoginItem>(cc_uuid)
                     ->GetTotp(code)
                     ->Close();
                    
                int64_t refreshDate = (int64_t)code.remaining;
                NSInteger maxTimer = (NSInteger)code.period;
                NSString* codeValue = [NSString stringWithUTF8String: code.code.c_str()];

                return [[TOTPResult alloc] initWithRefreshDate:refreshDate maxTimer:maxTimer value:codeValue];
            }];

            NSMutableArray<NSString*>* websitesArray = [NSMutableArray arrayWithCapacity: c_website.size()];

            if (c_website.size() != 0) {
                std::optional<std::string> result = v_inst.DownloadIcon(c_website[0]);
                if (result.has_value()) {
                    NSString* path = [NSString stringWithUTF8String: result.value().c_str()];

                    img = [[ClientwardenImage alloc] initWithType:ImageTypeAppSupport path:path];
                } else {
                    img = [[ClientwardenImage alloc] initWithType:ImageTypeSystemImage path:@"globe"];
                }
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
                NSDate* date = [NSDate dateWithTimeIntervalSince1970: (NSTimeInterval)c_pass.first];
                NSString* s_date = [NSDateFormatter localizedStringFromDate:date
                                                    dateStyle:NSDateFormatterMediumStyle
                                                    timeStyle:NSDateFormatterShortStyle];
                   
                PasswordHistoryItem* item = [[PasswordHistoryItem alloc] initWithDate:s_date password:pass];
                [passwordHistory addObject: item];
                OPENSSL_cleanse(c_pass.second.data(), c_pass.second.size());
                c_pass.second.clear();
            }
                
            OPENSSL_cleanse(c_username.data(), c_username.size());
            c_username.clear();
            OPENSSL_cleanse(c_password.data(), c_password.size());
            c_password.clear();
            OPENSSL_cleanse(c_totp.data(), c_totp.size());
            c_totp.clear();
        } else if (c_type == ClientWarden::CipherType::Card) {
            std::string c_brand = "";
            std::string c_cardholderName = "";
            std::string c_code = "";
            std::string c_expMonth = "";
            std::string c_expYear = "";
            std::string c_number = "";

            v_inst.GetItem<ClientWarden::CardItem>(c_uuid)
                 ->GetBrand(c_brand)
                 ->GetCardholderName(c_cardholderName)
                 ->GetCode(c_code)
                 ->GetExpMonth(c_expMonth)
                 ->GetExpYear(c_expYear)
                 ->GetNumber(c_number)
                 ->Close();

            NSString* brand = [NSString stringWithUTF8String: c_brand.c_str()];
            NSString* cardholderName = [NSString stringWithUTF8String: c_cardholderName.c_str()];
            NSString* code = [NSString stringWithUTF8String: c_code.c_str()];
            NSString* expiration = [NSString stringWithUTF8String: (c_expMonth + "/" + c_expYear).c_str()];
            NSString* number = [NSString stringWithUTF8String: c_number.c_str()];

            GenericItemData* brandItem = [[GenericItemData alloc] initWithTitle: @"Brand"
                                                                  value: brand
                                                                  type:GenericItemTypeGeneric];

            GenericItemData* cardholderNameItem = [[GenericItemData alloc] initWithTitle: @"Cardholder Name"
                                                                           value: cardholderName
                                                                           type:GenericItemTypeGeneric];

            GenericItemData* numberItem = [[GenericItemData alloc] initWithTitle: @"Number"
                                                                   value: number
                                                                   type:GenericItemTypePassword];

            GenericItemData* codeItem = [[GenericItemData alloc] initWithTitle: @"Code"
                                                                 value: code
                                                                 type:GenericItemTypePassword];

            GenericItemData* expirationItem = [[GenericItemData alloc] initWithTitle: @"Expiration Date"
                                                                       value: expiration
                                                                       type:GenericItemTypeDate];
                
            [itemFields addObject: brandItem];
            [itemFields addObject: cardholderNameItem];
            [itemFields addObject: numberItem];
            [itemFields addObject: codeItem];
            [itemFields addObject: expirationItem];

            img = [[ClientwardenImage alloc] initWithType:ImageTypeSystemImage path:@"creditcard"];
              
            OPENSSL_cleanse(c_brand.data(), c_brand.size());
            c_brand.clear();
            OPENSSL_cleanse(c_cardholderName.data(), c_cardholderName.size());
            c_cardholderName.clear();
            OPENSSL_cleanse(c_code.data(), c_code.size());
            c_code.clear();
            OPENSSL_cleanse(c_expMonth.data(), c_expMonth.size());
            c_expMonth.clear();
            OPENSSL_cleanse(c_expYear.data(), c_expYear.size());
            c_expYear.clear();
            OPENSSL_cleanse(c_number.data(), c_number.size());
            c_number.clear();
        } else if (c_type == ClientWarden::CipherType::Identity) {
            std::string c_addr1 = "";
            std::string c_addr2 = "";
            std::string c_addr3 = "";
            std::string c_city = "";
            std::string c_company = "";
            std::string c_country = "";
            std::string c_email = "";
            std::string c_firstName = "";
            std::string c_middleName = "";
            std::string c_lastName = "";
            std::string c_licenseNum = "";
            std::string c_passportNum = "";
            std::string c_phone = "";
            std::string c_postalCode = "";
            std::string c_ssn = "";
            std::string c_state = "";
            std::string c_title = "";
            std::string c_username = "";

            v_inst.GetItem<ClientWarden::IdentityItem>(c_uuid)
                 ->GetAddress1(c_addr1)
                 ->GetAddress2(c_addr2)
                 ->GetAddress3(c_addr3)
                 ->GetCity(c_city)
                 ->GetCompany(c_company)
                 ->GetCountry(c_country)
                 ->GetEmail(c_email)
                 ->GetFirstName(c_firstName)
                 ->GetLastName(c_lastName)
                 ->GetLicenceNumber(c_licenseNum)
                 ->GetMiddleName(c_middleName)
                 ->GetPassportNumber(c_passportNum)
                 ->GetPhone(c_phone)
                 ->GetPostalCode(c_postalCode)
                 ->GetSSN(c_ssn)
                 ->GetState(c_state)
                 ->GetTitle(c_title)
                 ->GetUsername(c_username)
                 ->Close();

            NSString* addr1 = [NSString stringWithUTF8String: c_addr1.c_str()];
            NSString* addr2 = [NSString stringWithUTF8String: c_addr2.c_str()];
            NSString* addr3 = [NSString stringWithUTF8String: c_addr3.c_str()];
            NSString* locality = [NSString stringWithUTF8String: (c_postalCode + ", " + c_city + ", " + c_state + ", " + c_country).c_str()];
            NSString* company = [NSString stringWithUTF8String: c_company.c_str()];
            NSString* email = [NSString stringWithUTF8String: c_email.c_str()];
            NSString* title = [NSString stringWithUTF8String: c_title.c_str()];
            NSString* firstName = [NSString stringWithUTF8String: c_firstName.c_str()];
            NSString* middleName = [NSString stringWithUTF8String: c_middleName.c_str()];
            NSString* lastName = [NSString stringWithUTF8String: c_lastName.c_str()];
            NSString* licenseNum = [NSString stringWithUTF8String: c_licenseNum.c_str()];
            NSString* passportNum = [NSString stringWithUTF8String: c_passportNum.c_str()];
            NSString* phone = [NSString stringWithUTF8String: c_phone.c_str()];
            NSString* ssn = [NSString stringWithUTF8String: c_ssn.c_str()];
            NSString* username = [NSString stringWithUTF8String: c_username.c_str()];

            GenericItemData* emailItem = [[GenericItemData alloc] initWithTitle: @"Email"
                                                                  value: email
                                                                  type:GenericItemTypeGeneric];

            GenericItemData* nameItem = [[GenericItemData alloc] initWithTitle: @"Name"
                                                                 value: title
                                                                 value_1: firstName
                                                                 value_2: middleName
                                                                 value_3: lastName];

            GenericItemData* usernameItem = [[GenericItemData alloc] initWithTitle: @"Username"
                                                                     value: username
                                                                     type:GenericItemTypeGeneric];

            GenericItemData* companyItem = [[GenericItemData alloc] initWithTitle: @"Company"
                                                                    value: company
                                                                    type:GenericItemTypeGeneric];

            GenericItemData* phoneItem = [[GenericItemData alloc] initWithTitle: @"Phone"
                                                                  value: phone
                                                                  type:GenericItemTypeGeneric];

            GenericItemData* ssnItem = [[GenericItemData alloc] initWithTitle: @"SSN"
                                                                value: ssn
                                                                type:GenericItemTypePassword];

            GenericItemData* passportNumItem = [[GenericItemData alloc] initWithTitle: @"Passport Number"
                                                                        value: passportNum
                                                                        type:GenericItemTypePassword];

            GenericItemData* licenseNumItem = [[GenericItemData alloc] initWithTitle: @"Licence Number"
                                                                       value: licenseNum
                                                                       type:GenericItemTypeGeneric];

            GenericItemData* addr1Item = [[GenericItemData alloc] initWithTitle: @"Address 1"
                                                                  value: addr1
                                                                  type:GenericItemTypeGeneric];

            GenericItemData* addr2Item = [[GenericItemData alloc] initWithTitle: @"Address 2"
                                                                  value: addr2
                                                                  type:GenericItemTypeGeneric];

            GenericItemData* addr3Item = [[GenericItemData alloc] initWithTitle: @"Address 3"
                                                                  value: addr3
                                                                  type:GenericItemTypeGeneric];

            GenericItemData* localityItem = [[GenericItemData alloc] initWithTitle: @"Locality"
                                                                     value: locality
                                                                     type:GenericItemTypeGeneric];
                
            [itemFields addObject: nameItem];
            [itemFields addObject: usernameItem];
            [itemFields addObject: companyItem];
            [itemFields addObject: ssnItem];
            [itemFields addObject: passportNumItem];
            [itemFields addObject: licenseNumItem];
            [itemFields addObject: emailItem];
            [itemFields addObject: phoneItem];
            [itemFields addObject: addr1Item];
            [itemFields addObject: addr2Item];
            [itemFields addObject: addr3Item];
            [itemFields addObject: localityItem];

            img = [[ClientwardenImage alloc] initWithType:ImageTypeSystemImage path:@"person.text.rectangle"];

            OPENSSL_cleanse(c_addr1.data(), c_addr1.size());
            c_addr1.clear();
            OPENSSL_cleanse(c_addr2.data(), c_addr2.size());
            c_addr2.clear();
            OPENSSL_cleanse(c_addr3.data(), c_addr3.size());
            c_addr3.clear();
            OPENSSL_cleanse(c_city.data(), c_city.size());
            c_city.clear();
            OPENSSL_cleanse(c_company.data(), c_company.size());
            c_company.clear();
            OPENSSL_cleanse(c_country.data(), c_country.size());
            c_country.clear();
            OPENSSL_cleanse(c_email.data(), c_email.size());
            c_email.clear();
            OPENSSL_cleanse(c_firstName.data(), c_firstName.size());
            c_firstName.clear();
            OPENSSL_cleanse(c_middleName.data(), c_middleName.size());
            c_middleName.clear();
            OPENSSL_cleanse(c_lastName.data(), c_lastName.size());
            c_lastName.clear();
            OPENSSL_cleanse(c_licenseNum.data(), c_licenseNum.size());
            c_licenseNum.clear();
            OPENSSL_cleanse(c_passportNum.data(), c_passportNum.size());
            c_passportNum.clear();
            OPENSSL_cleanse(c_phone.data(), c_phone.size());
            c_phone.clear();
            OPENSSL_cleanse(c_postalCode.data(), c_postalCode.size());
            c_postalCode.clear();
            OPENSSL_cleanse(c_ssn.data(), c_ssn.size());
            c_ssn.clear();
            OPENSSL_cleanse(c_state.data(), c_state.size());
            c_state.clear();
            OPENSSL_cleanse(c_title.data(), c_title.size());
            c_title.clear();
            OPENSSL_cleanse(c_username.data(), c_username.size());
            c_username.clear();
        } else if (c_type == ClientWarden::CipherType::Note) {
            img = [[ClientwardenImage alloc] initWithType:ImageTypeSystemImage path:@"pad.header"];
        } else if (c_type == ClientWarden::CipherType::SSHKey) {
            std::string c_fingerprint = "";
            std::string c_privKey = "";
            std::string c_pubKey = "";

            v_inst.GetItem<ClientWarden::SSHKeyItem>(c_uuid)
                 ->GetFingerprint(c_fingerprint)
                 ->GetPrivateKey(c_privKey)
                 ->GetPublicKey(c_pubKey)
                 ->Close();

            NSString* fingerprint = [NSString stringWithUTF8String: c_fingerprint.c_str()];
            NSString* privKey = [NSString stringWithUTF8String: c_privKey.c_str()];
            NSString* pubKey = [NSString stringWithUTF8String: c_pubKey.c_str()];

            GenericItemData* fingerprintItem = [[GenericItemData alloc] initWithTitle: @"Fingerprint"
                                                                        value: fingerprint
                                                                        type:GenericItemTypeGeneric];

            GenericItemData* privKeyItem = [[GenericItemData alloc] initWithTitle: @"Private Key"
                                                                    value: privKey
                                                                    type:GenericItemTypeMl_password];

            GenericItemData* pubKeyItem = [[GenericItemData alloc] initWithTitle: @"Public Key"
                                                                   value: pubKey
                                                                   type:GenericItemTypePassword];
                
            [itemFields addObject: fingerprintItem];
            [itemFields addObject: privKeyItem];
            [itemFields addObject: pubKeyItem];

            img = [[ClientwardenImage alloc] initWithType:ImageTypeSystemImage path:@"key.viewfinder"];
                
            OPENSSL_cleanse(c_fingerprint.data(), c_fingerprint.size());
            c_fingerprint.clear();
            OPENSSL_cleanse(c_privKey.data(), c_privKey.size());
            c_privKey.clear();
            OPENSSL_cleanse(c_pubKey.data(), c_pubKey.size());
            c_pubKey.clear();
        }

        [SidePanel.instance viewItemWithName:name uuid:uuid type:type icon:img repromptItem:reprompt folderUUID:folderUUID favorite:favorite 
                            itemFields:itemFields customFields:customFields itemHistory:itemHistory passwordHistory:passwordHistory 
                            attachmentItems:attachments notes:notes];

        return true;
    } catch (...) {
        dispatch_async(dispatch_get_main_queue(), ^{
            Toast* toast = [[Toast alloc] initWithMessage:@"Failed to View Item"];
            [[ToastStore instance] addToast:toast];
        });

        return false;
    }
}

+ (void)cb_sidebar {
    SidePanel.instance.cb_sidebar = ^BOOL(NSUUID* uuid) {
        ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

        std::string c_uuid = uuid.UUIDString.UTF8String;
        std::transform(c_uuid.begin(), c_uuid.end(), c_uuid.begin(), ::tolower);

        bool isReprompt = false;

        v_inst.GetItem(c_uuid)
             ->GetReprompt(isReprompt)
             ->Close();
        
        if (isReprompt) {
            [SidePanel.instance closeItem];
            SidePanel.instance.isReprompt = true;
            SidePanel.instance.repromptFailed = false;
            SidePanel.instance.uuid = uuid;
            SidePanel.instance.repromptPassword = @"";
            return YES;
        }
        return (BOOL)sidebar(uuid);
    };

    SidePanel.instance.cb_sidebarReprompt = ^BOOL(NSUUID* uuid, NSString* password) {
        ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();
        std::string c_password = password.UTF8String;

        if (v_inst.checkReprompt(c_password)) {
            OPENSSL_cleanse(c_password.data(), c_password.size());
            c_password.clear();

            SidePanel.instance.isReprompt = false;
            SidePanel.instance.repromptFailed = false;

            return (BOOL)sidebar(uuid);
        } else {
            OPENSSL_cleanse(c_password.data(), c_password.size());
            c_password.clear();
            
            SidePanel.instance.repromptFailed = true;

            return YES;
        }
    };
}

/*
 * Download Attachment uses a UUID and attachID to get the
 * attachment from the selected item and use an item picker
 * to determine where to save the item and save the item
 * while updating the progress bar of the download
 */
+ (void)cb_downloadAttachment {
    SidePanel.instance.cb_downloadAttachment = ^BOOL(NSUUID* uuid, NSString* attachID) {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

            std::string c_uuid = uuid.UUIDString.UTF8String;
            std::transform(c_uuid.begin(), c_uuid.end(), c_uuid.begin(), ::tolower);

            std::string c_attachID = attachID.UTF8String;

            std::string c_attachName = "";

            v_inst.GetItem(c_uuid)
                 ->GetAttachmentName(c_attachID, c_attachName)
                 ->Close();

            NSSavePanel* panel = [NSSavePanel savePanel];
            panel.nameFieldStringValue = [NSString stringWithUTF8String: c_attachName.c_str()];
            panel.canCreateDirectories = YES;

            [panel beginWithCompletionHandler:^(NSModalResponse result) {
                if (result == NSModalResponseOK && panel.URL) {
                    std::string path = panel.URL.path.UTF8String;

                    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{

                        v_inst.GetItem(c_uuid)
                             ->GetAttachment(c_attachID, path, [attachID](float progress) {
                                   dispatch_async(dispatch_get_main_queue(), ^{
                                       [SidePanel.instance updateProgressWithId:attachID progress:(double)progress];
                                   });
                             })
                             ->Close();

                        dispatch_async(dispatch_get_main_queue(), ^{
                            [SidePanel.instance updateProgressWithId:attachID progress:0.0];
                        });
                    });
                } else {
                    dispatch_async(dispatch_get_main_queue(), ^{
                        Toast* toast = [[Toast alloc] initWithMessage:@"Failed to get Download Location"];
                        [[ToastStore instance] addToast:toast];
                    });
                }
            }];

            return YES;
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to Download Attachment"];
                [[ToastStore instance] addToast:toast];
            });

            return NO;
        }
    };
}

/*
 * Upload Attachment uses a UUID to upload the 
 * selected file with NSOpenPanel to the selected
 * item while updating the upload progress bar.
 * If the item is over 500MB, it will not be uploaded.
 */
+ (void)cb_uploadAttachment {
    SidePanel.instance.cb_uploadAttachment = ^BOOL(NSUUID* uuid) {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

            std::string c_uuid = uuid.UUIDString.UTF8String;
            std::transform(c_uuid.begin(), c_uuid.end(), c_uuid.begin(), ::tolower);

            NSOpenPanel* panel = [NSOpenPanel openPanel];
            panel.canChooseFiles = YES;
            panel.canChooseDirectories = NO;
            panel.allowsMultipleSelection = NO;

            [panel beginWithCompletionHandler:^(NSModalResponse result) {
                if (result == NSModalResponseOK && panel.URL) {
                    NSString* path = panel.URL.path;
                    NSString* fileName = panel.URL.lastPathComponent;

                    NSError* attrRes = nil;
                    NSDictionary* attrs = [[NSFileManager defaultManager] attributesOfItemAtPath:path error:&attrRes];

                    if (attrs) {
                        uint64_t fileSize = [attrs fileSize];
                        uint64_t maxSize = 500ULL * 1024 * 1024;

                        if (fileSize > maxSize) {
                            dispatch_async(dispatch_get_main_queue(), ^{
                                Toast* toast = [[Toast alloc] initWithMessage:@"Attachment too big"];
                                [[ToastStore instance] addToast:toast];
                            });
                            return;
                        }
                    } else {
                        dispatch_async(dispatch_get_main_queue(), ^{
                            Toast* toast = [[Toast alloc] initWithMessage:@"Failed to Get File Attributes"];
                            [[ToastStore instance] addToast:toast];
                        });
                        return;
                    }

                    NSString* tempAttachID = [[NSUUID UUID] UUIDString];

                    AttachmentItemData* attachmentItem = [[AttachmentItemData alloc] initWithAttachID:tempAttachID name:fileName];

                    dispatch_async(dispatch_get_main_queue(), ^{
                        [SidePanel.instance addAttachmentItem:attachmentItem];
                    });

                    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                        NSError* res = nil;
                        NSData* fileData = [NSData dataWithContentsOfFile:path options:0 error:&res];

                        if (!fileData) {
                            dispatch_async(dispatch_get_main_queue(), ^{
                                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to Read File"];
                                [[ToastStore instance] addToast:toast];
                                [SidePanel.instance deleteAttachmentViewWithId:tempAttachID];
                            });
                            return;
                        }

                        std::string c_content((const char*)fileData.bytes, fileData.length);
                        std::string c_fileName = fileName.UTF8String;

                        std::string c_newAttachID = "";

                        v_inst.GetItem(c_uuid)
                             ->AddAttachment(c_fileName, c_content, c_newAttachID, [tempAttachID](float progress) {
                               dispatch_async(dispatch_get_main_queue(), ^{
                                   [SidePanel.instance updateProgressWithId:tempAttachID progress:(double)progress];
                               });
                             })
                             ->Commit();

                        NSString* attachID = [NSString stringWithUTF8String: c_newAttachID.c_str()];

                        dispatch_async(dispatch_get_main_queue(), ^{
                            [SidePanel.instance updateAttachIDWithId:tempAttachID attachID:attachID];
                            [SidePanel.instance updateProgressWithId:attachID progress:0.0];
                        });
                    });
                } else {
                    dispatch_async(dispatch_get_main_queue(), ^{
                        Toast* toast = [[Toast alloc] initWithMessage:@"Failed to Get Upload Item"];
                        [[ToastStore instance] addToast:toast];
                    });
                }
            }];

            return YES;
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to Remove Attachment"];
                [[ToastStore instance] addToast:toast];
            });

            return NO;
        }
    };
}

/*
 * Remove Attachment uses a UUID and attachment ID to
 * remove the attachment from the selected item while
 * returning a result bool
 */
+ (void)cb_removeAttachment {
    SidePanel.instance.cb_removeAttachment = ^BOOL(NSUUID* uuid, NSString* attachID) {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

            std::string c_uuid = uuid.UUIDString.UTF8String;
            std::transform(c_uuid.begin(), c_uuid.end(), c_uuid.begin(), ::tolower);

            std::string c_attachID = attachID.UTF8String;

            v_inst.GetItem(c_uuid)
                 ->RemoveAttachment(c_attachID)
                 ->Commit();

            [SidePanel.instance deleteAttachmentViewWithId:attachID];

            return YES;
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to Remove Attachment"];
                [[ToastStore instance] addToast:toast];
            });

            return NO;
        }
    };
}

/*
 * Save Item uses a UUID and returns a bool.
 * First it reads Sidepanel.instance to get
 * all the values, it then overrides all the
 * values from the vault with the new ones.
 * This is pretty much the only way, since
 * we do not track changes and it would be 
 * less efficient.
 */
+ (void)cb_save {
    SidePanel.instance.cb_save = ^BOOL(NSUUID* uuid, NSString* name, ItemType type, BOOL reprompt, NSUUID* folderUUID, 
                                       NSArray<GenericItemData*>* itemFields, NSArray<FieldItemData*>* customFields, NSString* notes) {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

            std::string c_uuid = uuid.UUIDString.UTF8String;
            std::transform(c_uuid.begin(), c_uuid.end(), c_uuid.begin(), ::tolower);
            
            std::shared_ptr<ClientWarden::GenericItem> item = v_inst.GetItem(c_uuid);

            item->ClearFields();

            for (FieldItemData* field in customFields) {
                std::string c_title;
                std::string c_value;
                ClientWarden::CustomFieldType c_type;

                c_title = field.title.UTF8String;
                c_value = field.value.UTF8String;
                c_type = (ClientWarden::CustomFieldType)((int)field.type);

                item->AddField(c_type, c_title, c_value);

                OPENSSL_cleanse((void*)c_title.data(), c_title.size());
                c_title.clear();
                OPENSSL_cleanse((void*)c_value.data(), c_value.size());
                c_value.clear();
            }

            std::string c_notes = notes.UTF8String;
            std::string c_name = name.UTF8String;

            std::string c_folderUUID = folderUUID.UUIDString.UTF8String;
            std::transform(c_folderUUID.begin(), c_folderUUID.end(), c_folderUUID.begin(), ::tolower);

            if (c_folderUUID != "00000000-0000-0000-0000-000000000000") {
                item->SetFolder(c_folderUUID);
            } else {
                item->RemoveFolder();
            }

            item->SetNotes(c_notes)
                ->SetName(c_name)
                ->SetReprompt((bool)reprompt)
                ->Commit();

            OPENSSL_cleanse((void*)c_name.data(), c_name.size());
            c_name.clear();
            OPENSSL_cleanse((void*)c_notes.data(), c_notes.size());
            c_notes.clear();

            if (type == ItemTypeLogin) {
                std::shared_ptr<ClientWarden::LoginItem> litem = v_inst.GetItem<ClientWarden::LoginItem>(c_uuid);

                std::string c_username = "";
                std::string c_password = "";
                std::string c_totp = "";
                std::vector<std::string> c_website;

                for (GenericItemData* itemField in itemFields) {
                    if (itemField.title == @"Username") {
                        c_username = itemField.value.UTF8String;
                    } else if (itemField.title == @"Password") {
                        c_password = itemField.value.UTF8String;
                    } else if (itemField.title == @"Two Factor Authentication") {
                        c_totp = itemField.value.UTF8String;
                    } else if (itemField.title == @"Websites") {
                        std::istringstream stream(itemField.value.UTF8String);
                        std::string line;

                        while (std::getline(stream, line)) {
                            c_website.push_back(line);
                        }
                    }
                }

                litem->SetUsername(c_username)
                     ->SetPassword(c_password)
                     ->SetTotp(c_totp);
                
                std::vector<std::string> c_oWebsites;

                litem->GetWebsites(c_oWebsites);

                for (auto& website : c_oWebsites) {
                    litem->RemoveWebsite(website);

                    OPENSSL_cleanse((void*)website.data(), website.size());
                    website.clear();
                }

                for (auto& website : c_website) {
                    litem->AddWebsite(website);

                    OPENSSL_cleanse((void*)website.data(), website.size());
                    website.clear();
                }

                litem->Commit();

                OPENSSL_cleanse((void*)c_username.data(), c_username.size());
                c_username.clear();
                OPENSSL_cleanse((void*)c_password.data(), c_password.size());
                c_password.clear();
                OPENSSL_cleanse((void*)c_totp.data(), c_totp.size());
                c_totp.clear();
            } else if (type == ItemTypeCard) {
                std::string c_brand = "";
                std::string c_cardholderName = "";
                std::string c_number = "";
                std::string c_code = "";
                std::string c_expYear = "";
                std::string c_expMonth = "";

                for (GenericItemData* itemField in itemFields) {
                    if (itemField.title == @"Brand") {
                        c_brand = itemField.value.UTF8String;
                    } else if (itemField.title == @"Cardholder Name") {
                        c_cardholderName = itemField.value.UTF8String;
                    } else if (itemField.title == @"Number") {
                        c_number = itemField.value.UTF8String;
                    } else if (itemField.title == @"Code") {
                        c_code = itemField.value.UTF8String;
                    } else if (itemField.title == @"Expiration Date") {
                        std::string c_field = itemField.value.UTF8String;
                        size_t pos = c_field.find('/');
                        if (pos != std::string::npos) {
                            c_expMonth = c_field.substr(0, pos);
                            c_expYear = c_field.substr(pos + 1);
                        }
                    }
                }

                v_inst.GetItem<ClientWarden::CardItem>(c_uuid)
                     ->SetBrand(c_brand)
                     ->SetCardholderName(c_cardholderName)
                     ->SetCode(c_code)
                     ->SetExpMonth(c_expMonth)
                     ->SetExpYear(c_expYear)
                     ->SetNumber(c_number)
                     ->Commit();

                OPENSSL_cleanse((void*)c_brand.data(), c_brand.size());
                c_brand.clear();
                OPENSSL_cleanse((void*)c_cardholderName.data(), c_cardholderName.size());
                c_cardholderName.clear();
                OPENSSL_cleanse((void*)c_code.data(), c_code.size());
                c_code.clear();
                OPENSSL_cleanse((void*)c_expMonth.data(), c_expMonth.size());
                c_expMonth.clear();
                OPENSSL_cleanse((void*)c_expYear.data(), c_expYear.size());
                c_expYear.clear();
                OPENSSL_cleanse((void*)c_number.data(), c_number.size());
                c_number.clear();
            } else if (type == ItemTypeIdentity) {
                std::string c_addr1 = "";
                std::string c_addr2 = "";
                std::string c_addr3 = "";
                std::string c_city = "";
                std::string c_company = "";
                std::string c_country = "";
                std::string c_email = "";
                std::string c_firstName = "";
                std::string c_middleName = "";
                std::string c_lastName = "";
                std::string c_licenseNum = "";
                std::string c_passportNum = "";
                std::string c_phone = "";
                std::string c_postalCode = "";
                std::string c_ssn = "";
                std::string c_state = "";
                std::string c_title = "";
                std::string c_username = "";

                for (GenericItemData* itemField in itemFields) {
                    if (itemField.title == @"Email") {
                        c_email = itemField.value.UTF8String;
                    } else if (itemField.title == @"Name") {
                        c_title = itemField.value.UTF8String;
                        c_firstName = itemField.value_1.UTF8String;
                        c_middleName = itemField.value_2.UTF8String;
                        c_lastName = itemField.value_3.UTF8String;
                    } else if (itemField.title == @"Username") {
                        c_username = itemField.value.UTF8String;
                    } else if (itemField.title == @"Company") {
                        c_company = itemField.value.UTF8String;
                    } else if (itemField.title == @"Phone") {
                        c_phone = itemField.value.UTF8String;
                    } else if (itemField.title == @"SSN") {
                        c_ssn = itemField.value.UTF8String;
                    } else if (itemField.title == @"Passport Number") {
                        c_passportNum = itemField.value.UTF8String;
                    } else if (itemField.title == @"Licence Number") {
                        c_licenseNum = itemField.value.UTF8String;
                    } else if (itemField.title == @"Address 1") {
                        c_addr1 = itemField.value.UTF8String;
                    } else if (itemField.title == @"Address 2") {
                        c_addr2 = itemField.value.UTF8String;
                    } else if (itemField.title == @"Address 3") {
                        c_addr3 = itemField.value.UTF8String;
                    } else if (itemField.title == @"Locality") {
                        std::vector<std::string> parts;
                        boost::split(parts, itemField.value.UTF8String, boost::is_any_of(", "), boost::token_compress_on);
                        c_postalCode = (parts.size() > 0) ? parts[0] : "";
                        c_city = (parts.size() > 1) ? parts[1] : "";
                        c_state = (parts.size() > 2) ? parts[2] : "";
                        c_country = (parts.size() > 3) ? parts[3] : "";
                    }
                }

                v_inst.GetItem<ClientWarden::IdentityItem>(c_uuid)
                     ->SetAddress1(c_addr1)
                     ->SetAddress2(c_addr2)
                     ->SetAddress3(c_addr3)
                     ->SetCity(c_city)
                     ->SetCompany(c_company)
                     ->SetCountry(c_country)
                     ->SetEmail(c_email)
                     ->SetFirstName(c_firstName)
                     ->SetLastName(c_lastName)
                     ->SetLicenceNumber(c_licenseNum)
                     ->SetMiddleName(c_middleName)
                     ->SetPassportNumber(c_passportNum)
                     ->SetPhone(c_phone)
                     ->SetPostalCode(c_postalCode)
                     ->SetSSN(c_ssn)
                     ->SetState(c_state)
                     ->SetTitle(c_title)
                     ->SetUsername(c_username)
                     ->Commit();

                OPENSSL_cleanse((void*)c_addr1.data(), c_addr1.size());
                c_addr1.clear();
                OPENSSL_cleanse((void*)c_addr2.data(), c_addr2.size());
                c_addr2.clear();
                OPENSSL_cleanse((void*)c_addr3.data(), c_addr3.size());
                c_addr3.clear();
                OPENSSL_cleanse((void*)c_city.data(), c_city.size());
                c_city.clear();
                OPENSSL_cleanse((void*)c_company.data(), c_company.size());
                c_company.clear();
                OPENSSL_cleanse((void*)c_country.data(), c_country.size());
                c_country.clear();
                OPENSSL_cleanse((void*)c_email.data(), c_email.size());
                c_email.clear();
                OPENSSL_cleanse((void*)c_firstName.data(), c_firstName.size());
                c_firstName.clear();
                OPENSSL_cleanse((void*)c_lastName.data(), c_lastName.size());
                c_lastName.clear();
                OPENSSL_cleanse((void*)c_licenseNum.data(), c_licenseNum.size());
                c_licenseNum.clear();
                OPENSSL_cleanse((void*)c_middleName.data(), c_middleName.size());
                c_middleName.clear();
                OPENSSL_cleanse((void*)c_passportNum.data(), c_passportNum.size());
                c_passportNum.clear();
                OPENSSL_cleanse((void*)c_phone.data(), c_phone.size());
                c_phone.clear();
                OPENSSL_cleanse((void*)c_postalCode.data(), c_postalCode.size());
                c_postalCode.clear();
                OPENSSL_cleanse((void*)c_ssn.data(), c_ssn.size());
                c_ssn.clear();
                OPENSSL_cleanse((void*)c_state.data(), c_state.size());
                c_state.clear();
                OPENSSL_cleanse((void*)c_title.data(), c_title.size());
                c_title.clear();
                OPENSSL_cleanse((void*)c_username.data(), c_username.size());
                c_username.clear();
            } else if (type == ItemTypeSSHKey) {
                std::string c_fingerprint = "";
                std::string c_privKey = "";
                std::string c_pubKey = "";

                for (GenericItemData* itemField in itemFields) {
                    if (itemField.title == @"Fingerprint") {
                        c_fingerprint = itemField.value.UTF8String;
                    } else if (itemField.title == @"Private Key") {
                        c_privKey = itemField.value.UTF8String;
                    } else if (itemField.title == @"Public Key") {
                        c_pubKey = itemField.value.UTF8String;
                    }
                }

                v_inst.GetItem<ClientWarden::SSHKeyItem>(c_uuid)
                     ->SetFingerprint(c_fingerprint)
                     ->SetPrivateKey(c_privKey)
                     ->SetPublicKey(c_pubKey)
                     ->Commit();

                OPENSSL_cleanse((void*)c_fingerprint.data(), c_fingerprint.size());
                c_fingerprint.clear();
                OPENSSL_cleanse((void*)c_privKey.data(), c_privKey.size());
                c_privKey.clear();
                OPENSSL_cleanse((void*)c_pubKey.data(), c_pubKey.size());
                c_pubKey.clear();
            }

            return YES;
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to Save Item"];
                [[ToastStore instance] addToast:toast];
            });

            return NO;
        }
    };
}

/*
 * Generate a random Password using Letters, Symbols (optional),
 * Capital Letters (optional) and numbers (optional) using a size.
 * EG:
 * Numbers = True, Symbols = True, Caps = True, Size = 8
 * = iG4h!uC#
 */
+ (void)cb_genRandPasswd {
    SidePanel.instance.cb_genRandPasswd = ^NSString* (BOOL numbers, BOOL symbols, BOOL caps, NSInteger size) {
        try {
            ClientWarden::PasswordGenerator passwordGen;

            std::string c_password = "";
            
            passwordGen.Random(size, (bool)numbers, (bool)symbols, (bool)caps, c_password);

            NSString* password = [NSString stringWithUTF8String:c_password.c_str()];

            return password;
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to Generate Random Password"];
                [[ToastStore instance] addToast:toast];
            });
            
            return @"";
        }
    };
}

/*
 * Generate a memorable Password using Words using a size.
 * EG:
 * Caps = True, Size = 4
 * = Cats-password-heart-elephant
 */
+ (void)cb_genSimplPasswd {
    SidePanel.instance.cb_genSimplPasswd = ^NSString* (BOOL caps, NSInteger size) {
        try {
            ClientWarden::PasswordGenerator passwordGen;

            std::string c_password = "";
            
            passwordGen.Memorable(size, (bool)caps, c_password);

            NSString* password = [NSString stringWithUTF8String:c_password.c_str()];

            return password;
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to Generate Simple Password"];
                [[ToastStore instance] addToast:toast];
            });
            
            return @"";
        }
    };
}

/*
 * Generate a memorable Password using Words using a size.
 * EG:
 * Caps = True, Size = 4
 * = Cats-password-heart-elephant
 */
+ (void)cb_genPinPasswd {
    SidePanel.instance.cb_genPinPasswd = ^NSString* (NSInteger size) {
        try {
            ClientWarden::PasswordGenerator passwordGen;

            std::string c_password = "";
            
            passwordGen.Pin(size, c_password);

            NSString* password = [NSString stringWithUTF8String:c_password.c_str()];

            return password;
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to Generate Pin"];
                [[ToastStore instance] addToast:toast];
            });
            
            return @"";
        }
    };
}

@end