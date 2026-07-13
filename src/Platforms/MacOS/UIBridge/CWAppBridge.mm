#import "CWAppBridge.h"
#import <Cocoa/Cocoa.h>
#import "clientwarden-Swift.h"
#include "Vault.h"

@implementation CWAppBridge

/*
 * Setup Callbacks will be called inside of the swift class
 * onAppear. Setup Callbacks will setup all the necessary
 * callbacks for that class.
 */
+ (void)setupCallbacks {
    [self cb_getState];
    [self cb_lock];
}

/*
 * GetState decides whether to present the login view (if the user
 * hasn't logged in yet) or the unlock screen (if the user has
 * logged in).
 */
+ (void)cb_getState {
    ClientwardenWindow.instance.cb_getState = ^WindowState {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();
            if (v_inst.state == ClientWarden::AuthState::Unlockable) {
                return WindowStateUnlock;
            } else {
                return WindowStateLogin;
            }
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to Get State"];
                [[ToastStore instance] addToast:toast];
            });
            return WindowStateEmpty; //TODO: Add Error View
        }
    };
}

/*
 * lock, just asks the vault to clear passwordHashes and stuff.
 */
+ (void)cb_lock {
    ClientwardenWindow.instance.cb_lock = ^bool {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();
            return v_inst.Lock();
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to Lock Vault"];
                [[ToastStore instance] addToast:toast];
            });
            return false;
        }
    };
}

@end