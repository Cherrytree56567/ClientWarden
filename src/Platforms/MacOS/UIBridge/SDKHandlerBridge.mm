#import "SDKHandlerBridge.h"
#import <Cocoa/Cocoa.h>
#import "clientwarden-Swift.h"
#include <boost/algorithm/string/join.hpp>
#include <vector>
#include <string>
#include "Vault.h"
#include "LoginItem/LoginItem.h"

@implementation SDKHandlerBridge


/*
 * Setup Callbacks will be called inside of the swift class
 * in SDK Handler. Setup Callbacks will setup all the necessary
 * callbacks for that class.
 */
+ (void)setupCallbacks {
    [self cb_getLogins];
    [self cb_getTitle];
    [self cb_getUsername];
    [self cb_getPassword];
}

+ (void)cb_getLogins {
    SDKHandler.instance.cb_getLogins = ^NSString* (NSString* website) {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

            std::string c_website = website.UTF8String;

            std::vector<std::string> ciphers;
            
            ciphers = v_inst.GetCipherQuery()
                           ->FilterByUnbinned()
                            .FilterByUnarchived()
                            .FilterByType(ClientWarden::CipherType::Login)
                            .Get();
            
            std::vector<std::string> matchedCips;

            for (auto& cipher : ciphers) {
                if (cipher == "") {
                    continue;
                }
                
                std::vector<std::string> websites;

                v_inst.GetItem<ClientWarden::LoginItem>(cipher)
                     ->GetWebsites(websites)
                     ->Close();
                
                if (std::find(websites.begin(), websites.end(), c_website) != websites.end()) {
                    matchedCips.push_back(cipher);
                }

                websites.clear();
            }

            std::string result = boost::algorithm::join(matchedCips, ",");

            return [NSString stringWithUTF8String: result.c_str()];
        } catch (...) {
            /*
             * Put an error thing for the log here
             * DO NOT USE THE SWIFT TOASTS FOR THIS
             */

            return @"";
        }
    };
}

+ (void)cb_getTitle {
    SDKHandler.instance.cb_getTitle = ^NSString* (NSString* uuid) {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

            std::string c_uuid = uuid.UTF8String;
            std::transform(c_uuid.begin(), c_uuid.end(), c_uuid.begin(), ::tolower);

            if (c_uuid == "") {
                return @"";
            }

            std::string c_name = "";

            v_inst.GetItem(c_uuid)
                 ->GetName(c_name)
                 ->Close();

            return [NSString stringWithUTF8String: c_name.c_str()];
        } catch (...) {
            /*
             * Put an error thing for the log here
             * DO NOT USE THE SWIFT TOASTS FOR THIS
             */

            return @"";
        }
    };
}

+ (void)cb_getUsername {
    SDKHandler.instance.cb_getUsername = ^NSString* (NSString* uuid) {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

            std::string c_uuid = uuid.UTF8String;
            std::transform(c_uuid.begin(), c_uuid.end(), c_uuid.begin(), ::tolower);

            if (c_uuid == "") {
                return @"";
            }

            std::string c_username = "";
            ClientWarden::CipherType type;

            v_inst.GetItem(c_uuid)
                 ->GetType(type)
                 ->Close();
            
            if (type != ClientWarden::CipherType::Login) {
                /*
                 * TODO: Log an error here
                 */
                return @"";
            }

            v_inst.GetItem<ClientWarden::LoginItem>(c_uuid)
                 ->GetUsername(c_username)
                 ->Close();

            return [NSString stringWithUTF8String: c_username.c_str()];
        } catch (...) {
            /*
             * Put an error thing for the log here
             * DO NOT USE THE SWIFT TOASTS FOR THIS
             */

            return @"";
        }
    };
}

+ (void)cb_getPassword {
    SDKHandler.instance.cb_getPassword = ^NSString* (NSString* uuid) {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

            std::string c_uuid = uuid.UTF8String;
            std::transform(c_uuid.begin(), c_uuid.end(), c_uuid.begin(), ::tolower);

            if (c_uuid == "") {
                return @"";
            }

            std::string c_password = "";
            ClientWarden::CipherType type;

            v_inst.GetItem(c_uuid)
                 ->GetType(type)
                 ->Close();
            
            if (type != ClientWarden::CipherType::Login) {
                /*
                 * TODO: Log an error here
                 */
                return @"";
            }

            v_inst.GetItem<ClientWarden::LoginItem>(c_uuid)
                 ->GetPassword(c_password)
                 ->Close();

            return [NSString stringWithUTF8String: c_password.c_str()];
        } catch (...) {
            /*
             * Put an error thing for the log here
             * DO NOT USE THE SWIFT TOASTS FOR THIS
             */

            return @"";
        }
    };
}

@end