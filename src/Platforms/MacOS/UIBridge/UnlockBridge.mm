#import "UnlockBridge.h"
#import <Cocoa/Cocoa.h>
#import "clientwarden-Swift.h"
#include "Vault.h"

@implementation UnlockBridge

/*
 * Setup Callbacks will be called inside of the swift class
 * onAppear. Setup Callbacks will setup all the necessary
 * callbacks for that class.
 */
+ (void)setupCallbacks {
    [self cb_getInfo];
    [self cb_unlock];
}

/*
 * Get Info populates the Unlock View
 * with the user's name and the user's
 * profile picture (WIP)
 */
+ (void)cb_getInfo {
    Unlock.instance.cb_getInfo = ^bool {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

            std::string name = v_inst.profile.profileName();
            NSString *n_name = [NSString stringWithUTF8String: name.c_str()];

            dispatch_async(dispatch_get_main_queue(), ^{
                Unlock.instance.username = n_name;
            });

            return true;
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to Get Info"];
                [[ToastStore instance] addToast:toast];
            });

            return false;
        }
    };
}

/*
 * Unlock uses a String password to try to unlock
 * the encrypted vault and passes back a result
 * bool.
 */
+ (void)cb_unlock {
    Unlock.instance.cb_unlock = ^bool(NSString* password) {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

            std::string c_password = password.UTF8String;

            try {
                v_inst.Unlock(c_password);
            } catch (...) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    Toast* toast = [[Toast alloc] initWithMessage:@"Invalid Password"];
                    [[ToastStore instance] addToast:toast];
                });
                return false;
            }

            dispatch_async(dispatch_get_main_queue(), ^{
                ClientwardenWindow.instance.state = WindowStateVault;
            });

            return true;
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to Unlock Vault"];
                [[ToastStore instance] addToast:toast];
            });

            return false;
        }
    };
}

@end