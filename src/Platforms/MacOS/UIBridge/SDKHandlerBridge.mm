#import "SDKHandlerBridge.h"
#import <Cocoa/Cocoa.h>
#import "clientwarden-Swift.h"
#include <boost/algorithm/string/join.hpp>
#include <boost/url.hpp>
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
    [self cb_createPasskey];
    [self cb_getPasskeys];
    [self cb_getPasskeyInfo];
}

bool compareURLs(std::string url1, std::string url2) {
    /*
     * First, we need to get the boost url thing
     * for the first URL
     */
    std::optional<boost::urls::url> b_url1;

    boost::system::result<boost::urls::url_view> res_u1 = boost::urls::parse_uri(url1);
    if (res_u1.has_error()) {
        boost::system::result<boost::urls::url_view> res1 = boost::urls::parse_uri("https://" + url1);
        if (res1.has_error()) {
            return false;
        }
        b_url1 = boost::urls::url(res1.value());
    }
    b_url1 = boost::urls::url(res_u1.value());

    /*
     * Then, we need to get the boost url thing
     * for the second URL
     */
    std::optional<boost::urls::url> b_url2;

    boost::system::result<boost::urls::url_view> res_u2 = boost::urls::parse_uri(url2);
    if (res_u2.has_error()) {
        boost::system::result<boost::urls::url_view> res1 = boost::urls::parse_uri("https://" + url2);
        if (res1.has_error()) {
            return false;
        }
        b_url2 = boost::urls::url(res1.value());
    }
    b_url2 = boost::urls::url(res_u2.value());

    /*
     * Get the url of both URLs in a standardised
     * format.
     */
    std::string u_url1 = b_url1->host();
    std::string u_url2 = b_url2->host();

    /*
     * Make them lowercase
     * just in case
     */
    std::transform(u_url1.begin(), u_url1.end(), u_url1.begin(), ::tolower);
    std::transform(u_url2.begin(), u_url2.end(), u_url2.begin(), ::tolower);

    return u_url1 == u_url2;
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
                
                bool webMatched = false;
                for (auto& l_website : websites) {
                    if (compareURLs(l_website, c_website)) {
                        webMatched = true;
                        break;
                    }
                }

                if (webMatched) {
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

+ (void)cb_createPasskey {
    SDKHandler.instance.cb_createPasskey = ^NSString* (NSString* info) {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

            std::string c_info = info.UTF8String;

            if (c_info == "") {
                return @"";
            }

            std::vector<std::string> parts;

            /*
             * THis part is from claude, but the rest isnt
             */
            for (auto part : c_info | std::views::split(",")) {
                parts.emplace_back(part.begin(), part.end());
            }

            if (parts.size() != 4) {
                return @"";
            }

            std::string relyingPartyIdentifier = ClientWarden::b64DecodeString(parts[0]);
            std::string userName = ClientWarden::b64DecodeString(parts[1]);
            std::string userHandle = ClientWarden::b64DecodeString(parts[2]);
            std::string clientDataHash = ClientWarden::b64DecodeString(parts[3]);

            std::string credentialId = "";
            std::string attestationObject = "";

            bool res = v_inst.createPasskey(relyingPartyIdentifier, userName, userHandle, clientDataHash, credentialId, attestationObject);

            if (!res) {
                /*
                 * Log an error here
                 */
                return @"";
            }

            std::string result = ClientWarden::b64EncodeString(credentialId) + "," + ClientWarden::b64EncodeString(attestationObject);

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

+ (void)cb_getPasskeys {
    SDKHandler.instance.cb_getPasskeys = ^NSString* (NSString* website) {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

            std::string c_website = website.UTF8String;

            std::vector<std::string> ciphers;
            
            ciphers = v_inst.GetCipherQuery()
                           ->FilterByUnbinned()
                            .FilterByUnarchived()
                            .FilterByType(ClientWarden::CipherType::Login)
                            .FilterByPasskey()
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
                
                bool webMatched = false;
                for (auto& l_website : websites) {
                    if (compareURLs(l_website, c_website)) {
                        webMatched = true;
                        break;
                    }
                }

                if (webMatched) {
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

+ (void)cb_getPasskeyInfo {
    SDKHandler.instance.cb_getPasskeyInfo = ^NSString* (NSString* uuid) {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

            std::string c_uuid = uuid.UTF8String;
            std::transform(c_uuid.begin(), c_uuid.end(), c_uuid.begin(), ::tolower);

            if (c_uuid == "") {
                return @"";
            }

            std::string userHandle = "";
            std::string signature = "";
            std::string authenticatorData = "";
            std::string credentialID = "";

            bool res = v_inst.getPasskey(c_uuid, userHandle, signature, authenticatorData, credentialID);

            if (!res) {
                /*
                 * Log an error here
                 */
                return @"";
            }

            std::string result = ClientWarden::b64EncodeString(userHandle) + "," + ClientWarden::b64EncodeString(signature) + ","
                ClientWarden::b64EncodeString(authenticatorData) + "," + ClientWarden::b64EncodeString(credentialID);

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

@end